use super::*;

/// An nl80211-backed [`Link`] for management-frame I/O and radio setup.
pub struct NetlinkLink {
    sock: NetlinkSocket,
    family_id: u16,
    ifindex: u32,
    freq: u32,
    station_ssid: Option<Vec<u8>>,
    station_mac: Option<[u8; 6]>,
    station_bssid: Option<[u8; 6]>,
    station_pairwise_key: Vec<u8>,
    station_group_key: Option<(u8, Vec<u8>)>,
    station_authorized: bool,
}

impl NetlinkLink {
    /// Open nl80211, put `iface` into AP mode on `channel`, register for the
    /// management subtypes the AP handles, and subscribe to frame events.
    pub fn open(iface: &str, channel: u8) -> io::Result<NetlinkLink> {
        Self::open_with_type(iface, channel, NL80211_IFTYPE_AP, true, None)
    }

    /// Open a managed VIF for station-side management-frame injection.
    ///
    /// The client can receive over a monitor sibling while nl80211 transmits
    /// Authentication/Association frames through the driver's real managed
    /// TX path. This is needed by FullMAC-like drivers that expose monitor RX
    /// but silently discard AF_PACKET management injection.
    pub fn open_station(iface: &str, channel: u8, ssid: &[u8]) -> io::Result<NetlinkLink> {
        Self::open_with_type(
            iface,
            channel,
            NL80211_IFTYPE_STATION,
            false,
            Some(ssid.to_vec()),
        )
    }

    fn open_with_type(
        iface: &str,
        channel: u8,
        iftype: u32,
        register_frames: bool,
        station_ssid: Option<Vec<u8>>,
    ) -> io::Result<NetlinkLink> {
        let mut sock = NetlinkSocket::open()?;
        let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;

        let ifindex =
            unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let station_mac = if station_ssid.is_some() {
            let address = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))?;
            Some(
                crate::util::try_mac_to_bytes(address.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{iface} reported an invalid MAC address"),
                    )
                })?,
            )
        } else {
            None
        };
        let freq = msg::freq_for_channel(channel);

        // Put the interface into the requested mode.
        let seq = sock.next_seq();
        let set_if = GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, iftype));
        let _ = sock.request_ack(set_if); // best-effort; some drivers want START_AP

        // Set the operating channel/frequency.
        let seq = sock.next_seq();
        let set_ch = GenlMessage::new(family_id, NL80211_CMD_SET_CHANNEL, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq));
        let _ = sock.request_ack(set_ch);

        // Subscribe to the mlme multicast group so we receive frame events.
        if let Some(group) = mlme_group {
            let _ = sock.join_multicast(group);
        }

        // Register for the management subtypes we want delivered to userspace.
        if register_frames {
            for &subtype in &REGISTER_SUBTYPES {
                let seq = sock.next_seq();
                let reg = GenlMessage::new(family_id, NL80211_CMD_REGISTER_FRAME, 0, seq)
                    .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                    .attr(Attr::u16v(NL80211_ATTR_FRAME_TYPE, subtype))
                    .attr(Attr::bytes(NL80211_ATTR_FRAME_MATCH, &[]));
                let _ = sock.request_ack(reg);
            }
        }

        Ok(NetlinkLink {
            sock,
            family_id,
            ifindex,
            freq,
            station_ssid,
            station_mac,
            station_bssid: None,
            station_pairwise_key: Vec::new(),
            station_group_key: None,
            station_authorized: false,
        })
    }

    /// Transmit a station Authentication/Association request through cfg80211's
    /// userspace-SME commands. Drivers such as ath12k accept these while
    /// rejecting monitor-mode AF_PACKET management injection.
    pub fn send_station_management_ack(&mut self, frame: &[u8]) -> io::Result<()> {
        let dot11_frame = dot11::strip_radiotap(frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing radiotap header"))?;
        let parsed = dot11::Dot11::parse(dot11_frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed 802.11 frame"))?;
        if parsed.frame_type() != dot11::TYPE_MGMT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "station SME only accepts management frames",
            ));
        }
        let ssid = self.station_ssid.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "not opened as a station link")
        })?;
        let seq = self.sock.next_seq();
        let message = match parsed.subtype() {
            dot11::SUBTYPE_AUTH => {
                let auth = dot11::parse_auth(&parsed.body).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed Authentication request",
                    )
                })?;
                if auth.algo != dot11::AUTH_ALG_OPEN || auth.seq != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "only Open-System userspace-SME authentication is supported",
                    ));
                }
                GenlMessage::new(self.family_id, NL80211_CMD_AUTHENTICATE, 0, seq)
                    .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
                    .attr(Attr::bytes(NL80211_ATTR_MAC, &parsed.addr1))
                    .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, self.freq))
                    .attr(Attr::bytes(NL80211_ATTR_SSID, ssid))
                    .attr(Attr::u32(
                        NL80211_ATTR_AUTH_TYPE,
                        NL80211_AUTHTYPE_OPEN_SYSTEM,
                    ))
            }
            dot11::SUBTYPE_ASSOC_REQ => {
                let ies = parsed.body.get(4..).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short Association request")
                })?;
                let (group, pairwise, akm, mfp_required) = station_rsn_suites(ies)?;
                let mut associate = GenlMessage::new(self.family_id, NL80211_CMD_ASSOCIATE, 0, seq)
                    .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
                    .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
                    .attr(Attr::bytes(NL80211_ATTR_MAC, &parsed.addr1))
                    .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, self.freq))
                    .attr(Attr::bytes(NL80211_ATTR_SSID, ssid))
                    .attr(Attr::bytes(NL80211_ATTR_IE, ies))
                    .attr(Attr::u32(NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2))
                    .attr(Attr::u32(NL80211_ATTR_CIPHER_SUITES_PAIRWISE, pairwise))
                    .attr(Attr::u32(NL80211_ATTR_CIPHER_SUITE_GROUP, group))
                    .attr(Attr::u32(NL80211_ATTR_AKM_SUITES, akm))
                    .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT, &[]))
                    .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
                    .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_OVER_NL80211, &[]));
                if mfp_required {
                    associate =
                        associate.attr(Attr::u32(NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED));
                }
                associate
            }
            _ => return self.send_frame_ack(frame),
        };
        self.station_bssid = Some(parsed.addr1);
        self.sock.request_ack(message)
    }

    /// Send one EAPOL payload through the station controlled port.
    pub fn send_station_eapol_ack(&mut self, frame: &[u8], encrypt: bool) -> io::Result<()> {
        let dot11_frame = dot11::strip_radiotap(frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing radiotap header"))?;
        let parsed = dot11::Dot11::parse(dot11_frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed 802.11 frame"))?;
        let eapol = parsed.eapol_frame().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "frame is not plaintext EAPOL")
        })?;
        let bssid = self.station_bssid.unwrap_or(parsed.addr1);
        let seq = self.sock.next_seq();
        let mut message = GenlMessage::new(self.family_id, NL80211_CMD_CONTROL_PORT_FRAME, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
            .attr(Attr::bytes(NL80211_ATTR_MAC, &bssid))
            .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
            .attr(Attr::bytes(NL80211_ATTR_FRAME, eapol));
        if !encrypt {
            message = message.attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, &[]));
        }
        self.sock.request_ack(message)
    }

    /// Install the verified supplicant PTK/GTK into the managed interface
    /// before M4, without reinstalling unchanged material on retries.
    pub fn sync_station_keys(&mut self, client: &crate::client::Client) -> io::Result<()> {
        let Some(bssid) = self.station_bssid else {
            return Ok(());
        };
        let Some((pairwise, cipher)) = client.pairwise_key() else {
            self.station_authorized = false;
            self.station_pairwise_key.fill(0);
            self.station_pairwise_key.clear();
            if let Some((_, mut group)) = self.station_group_key.take() {
                group.fill(0);
            }
            return Ok(());
        };
        if self.station_pairwise_key != pairwise {
            self.install_station_key(Some(&bssid), 0, cipher.suite_selector(), pairwise, false)?;
            self.station_pairwise_key.fill(0);
            self.station_pairwise_key.extend_from_slice(pairwise);
            eprintln!("barely-cli: installed managed-station PTK");
        }
        if let Some((index, gtk)) = client.group_key() {
            let changed = self
                .station_group_key
                .as_ref()
                .is_none_or(|(old_index, old)| *old_index != index || old.as_slice() != gtk);
            if changed {
                self.install_station_key(None, index, WLAN_CIPHER_SUITE_CCMP, gtk, true)?;
                if let Some((_, mut old)) = self.station_group_key.take() {
                    old.fill(0);
                }
                self.station_group_key = Some((index, gtk.to_vec()));
                eprintln!("barely-cli: installed managed-station GTK index={index}");
            }
        }
        if client.connected == 4 && !self.station_authorized {
            let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
            let mut flags = bit.to_ne_bytes().to_vec();
            flags.extend_from_slice(&bit.to_ne_bytes());
            let seq = self.sock.next_seq();
            let authorize = GenlMessage::new(self.family_id, NL80211_CMD_SET_STATION, 0, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
                .attr(Attr::bytes(NL80211_ATTR_MAC, &bssid))
                .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags));
            self.sock.request_ack(authorize)?;
            self.station_authorized = true;
            eprintln!("barely-cli: managed-station controlled port authorized");
        }
        Ok(())
    }

    fn install_station_key(
        &mut self,
        peer: Option<&[u8; 6]>,
        index: u8,
        cipher: u32,
        material: &[u8],
        make_default: bool,
    ) -> io::Result<()> {
        let key = [
            Attr::bytes(NL80211_KEY_DATA, material),
            Attr::u32(NL80211_KEY_CIPHER, cipher),
            Attr::u8(NL80211_KEY_IDX, index),
        ];
        let seq = self.sock.next_seq();
        let mut message = GenlMessage::new(self.family_id, NL80211_CMD_NEW_KEY, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
            .attr(Attr::nested_unflagged(NL80211_ATTR_KEY, &key));
        if let Some(peer) = peer {
            message = message.attr(Attr::bytes(NL80211_ATTR_MAC, peer));
        }
        self.sock.request_ack(message)?;
        if make_default {
            let seq = self.sock.next_seq();
            let default = GenlMessage::new(self.family_id, NL80211_CMD_SET_KEY, 0, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
                .attr(Attr::nested_unflagged(
                    NL80211_ATTR_KEY,
                    &[
                        Attr::u8(NL80211_KEY_IDX, index),
                        Attr::bytes(NL80211_KEY_DEFAULT, &[]),
                        Attr::nested(
                            NL80211_KEY_DEFAULT_TYPES,
                            &[Attr::bytes(NL80211_KEY_DEFAULT_TYPE_MULTICAST, &[])],
                        ),
                    ],
                ));
            self.sock.request_ack(default)?;
        }
        Ok(())
    }

    /// Send one bare management frame and wait for the kernel's command ACK.
    pub fn send_frame_ack(&mut self, frame: &[u8]) -> io::Result<()> {
        let dot11_frame = dot11::strip_radiotap(frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing radiotap header"))?;
        let seq = self.sock.next_seq();
        let message = GenlMessage::new(self.family_id, NL80211_CMD_FRAME, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, self.freq))
            .attr(Attr::bytes(NL80211_ATTR_FRAME, dot11_frame));
        self.sock.request_ack(message)
    }
}

impl Drop for NetlinkLink {
    fn drop(&mut self) {
        self.station_pairwise_key.fill(0);
        if let Some((_, key)) = self.station_group_key.as_mut() {
            key.fill(0);
        }
    }
}

impl Link for NetlinkLink {
    fn try_recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let buf = self.sock.recv(timeout)?;
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != self.family_id {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            match parsed.genl_cmd() {
                Some(
                    NL80211_CMD_FRAME
                    | NL80211_CMD_AUTHENTICATE
                    | NL80211_CMD_ASSOCIATE
                    | NL80211_CMD_DEAUTHENTICATE
                    | NL80211_CMD_DISASSOCIATE,
                ) => {
                    if let Some(frame) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) {
                        let mut out = dot11::RADIOTAP_TX.to_vec();
                        out.extend_from_slice(frame);
                        return Some(out);
                    }
                }
                Some(NL80211_CMD_CONTROL_PORT_FRAME) => {
                    let eapol = msg::find_attr(&attrs, NL80211_ATTR_FRAME)?;
                    let source = msg::find_attr(&attrs, NL80211_ATTR_MAC)
                        .filter(|source| source.len() == 6)?;
                    let sta = self.station_mac?;
                    let mut bssid = [0u8; 6];
                    bssid.copy_from_slice(source);
                    self.station_bssid = Some(bssid);
                    let mut out = dot11::RADIOTAP_TX.to_vec();
                    out.extend_from_slice(&[0x08, dot11::FC_FROMDS, 0, 0]);
                    out.extend_from_slice(&sta);
                    out.extend_from_slice(&bssid);
                    out.extend_from_slice(&bssid);
                    out.extend_from_slice(&[0, 0]);
                    out.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]);
                    out.extend_from_slice(eapol);
                    return Some(out);
                }
                _ => {}
            }
        }
        None
    }

    fn send(&mut self, frame: &[u8]) {
        // Strip the radiotap header; nl80211 carries the bare 802.11 frame.
        let Some(dot11_frame) = dot11::strip_radiotap(frame) else {
            return;
        };
        let seq = self.sock.next_seq();
        let m = GenlMessage::new(self.family_id, NL80211_CMD_FRAME, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, self.ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, self.freq))
            .attr(Attr::bytes(NL80211_ATTR_FRAME, dot11_frame));
        let _ = self.sock.send(&m.to_bytes(self.sock.pid));
    }
}

fn station_rsn_suites(ies: &[u8]) -> io::Result<(u32, u32, u32, bool)> {
    let mut offset = 0usize;
    while offset + 2 <= ies.len() {
        let length = ies[offset + 1] as usize;
        let end = offset + 2 + length;
        if end > ies.len() {
            break;
        }
        if ies[offset] == 48 {
            let rsn = &ies[offset + 2..end];
            if rsn.len() < 18 || u16::from_le_bytes([rsn[0], rsn[1]]) != 1 {
                break;
            }
            let group = u32::from_be_bytes(rsn[2..6].try_into().unwrap());
            let pairwise_count = u16::from_le_bytes([rsn[6], rsn[7]]) as usize;
            let pairwise_end = 8usize.saturating_add(pairwise_count.saturating_mul(4));
            if pairwise_count == 0 || pairwise_end + 2 > rsn.len() {
                break;
            }
            let pairwise = u32::from_be_bytes(rsn[8..12].try_into().unwrap());
            let akm_count = u16::from_le_bytes([rsn[pairwise_end], rsn[pairwise_end + 1]]) as usize;
            let akm_start = pairwise_end + 2;
            let akm_end = akm_start.saturating_add(akm_count.saturating_mul(4));
            if akm_count == 0 || akm_end > rsn.len() {
                break;
            }
            let akm = u32::from_be_bytes(rsn[akm_start..akm_start + 4].try_into().unwrap());
            let capabilities = rsn
                .get(akm_end..akm_end + 2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0);
            return Ok((group, pairwise, akm, capabilities & (1 << 6) != 0));
        }
        offset = end;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Association request has no valid RSN element",
    ))
}

// ---------------------------------------------------------------------------
// Kernel-offload AP (the "netlink way"): the kernel beacons (NL80211_CMD_START_AP)
// and does data-plane CCMP (NL80211_CMD_NEW_KEY); the 4-way handshake itself runs
// in `Ap`, with management frames exchanged over NL80211_CMD_FRAME.
// ---------------------------------------------------------------------------
