use super::*;

// Hot-path nl80211 event dispatch and protocol timers.

impl RadioRuntime {
    pub(super) fn receive_events(&mut self) -> io::Result<()> {
        let ifindex = self.topology.ifindex;
        // Management frames (auth/assoc) and EAPOL (control port over nl80211)
        // arrive on the event socket. Poll at 20 ms so the tick() below can fire
        // the 100-ms first EAPOL retransmit promptly on an idle loop.
        if let Some(len) = self
            .io
            .events
            .recv_into(Duration::from_millis(20), &mut self.event_buffer)
        {
            for parsed in msg::messages(&self.event_buffer[..len]) {
                if parsed.typ != self.io.family {
                    continue;
                }
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                // Multiple independently-running radios subscribe to the same
                // nl80211 multicast groups. Never let a management, TX-status,
                // control-port, or radar event for another netdev reach this
                // radio's AP state machine. Events from this radio's own
                // AP_VLAN children still belong to it: mac80211 delivers a
                // control-port EAPOL from a per-STA-VIF station (group-rekey
                // m2, rejoin) with the AP_VLAN's ifindex, not the AP's.
                if msg::find_attr(&attrs, NL80211_ATTR_IFINDEX)
                    .and_then(native_u32)
                    .is_some_and(|event_ifindex| {
                        event_ifindex != ifindex && !self.vlans.ifindices.contains(&event_ifindex)
                    })
                {
                    continue;
                }
                if crate::util::netlink_debug_enabled() {
                    if let Some(c) = parsed.genl_cmd() {
                        if c == NL80211_CMD_FRAME || c == NL80211_CMD_CONTROL_PORT_FRAME {
                            let sub = msg::find_attr(&attrs, NL80211_ATTR_FRAME)
                                .and_then(|f| f.first().copied())
                                .map(|b| b & 0xfc)
                                .unwrap_or(0xff);
                            eprintln!("netlink AP: RX cmd={c} frame_subtype=0x{sub:02x}");
                        }
                    }
                }
                // 802.11 ACK status for a control-port EAPOL we sent. The event
                // carries the sent frame (Ethernet-framed: dst||src||etype||PDU),
                // so the destination MAC is its first 6 bytes; NL80211_ATTR_ACK is
                // present iff the STA acknowledged it. Feed this to the AP so its
                // retransmit is ACK-driven (resend fast until the STA got it).
                if parsed.genl_cmd() == Some(NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS) {
                    if let Some(fr) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) {
                        if fr.len() >= 6 && msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some() {
                            let mut dst = [0u8; 6];
                            dst.copy_from_slice(&fr[..6]);
                            // Map an MLD or affiliated-link destination to the
                            // association-link station the core tracks.
                            let sta = self.ap.station_link_for_peer(&dst).unwrap_or(dst);
                            self.ap.note_eapol_acked(&sta);
                        }
                    }
                    if crate::util::netlink_debug_enabled() {
                        let acked = msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some();
                        let flen = msg::find_attr(&attrs, NL80211_ATTR_FRAME)
                            .map(|f| f.len())
                            .unwrap_or(0);
                        eprintln!("netlink AP: EAPOL TX-STATUS acked={acked} frame_len={flen}");
                    }
                    continue;
                }
                // reference AP pre-adds the kernel station, sends the successful
                // (Re)Association Response, and starts WPA only from this TX-
                // status callback. Mirror that ordering: release the held m1/m3
                // only after an 802.11 ACK. If the response was not ACKed, remove
                // the station we added early so a later association starts clean.
                if parsed.genl_cmd() == Some(NL80211_CMD_FRAME_TX_STATUS) {
                    let acked = msg::find_attr(&attrs, NL80211_ATTR_ACK).is_some();
                    let Some(fr) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) else {
                        continue;
                    };
                    let Some(tx) = dot11::Dot11::parse(fr) else {
                        continue;
                    };
                    if tx.subtype() == dot11::SUBTYPE_AUTH {
                        let (seq, status) = if tx.body.len() >= 6 {
                            (
                                u16::from_le_bytes([tx.body[2], tx.body[3]]),
                                u16::from_le_bytes([tx.body[4], tx.body[5]]),
                            )
                        } else {
                            (0, 0)
                        };
                        eprintln!(
                        "netlink AP: AUTH TX-STATUS dst={} seq={seq} status={status} acked={acked} link={:?}",
                        crate::util::bytes_to_mac(&tx.addr1),
                        msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                            .and_then(|v| v.first()),
                    );
                    }
                    let is_assoc_resp = matches!(
                        tx.subtype(),
                        dot11::SUBTYPE_ASSOC_RESP | dot11::SUBTYPE_REASSOC_RESP
                    );
                    let success = is_assoc_resp
                        && tx.body.len() >= 6
                        && u16::from_le_bytes([tx.body[2], tx.body[3]]) == 0;
                    if !success || fr.len() < 24 {
                        continue;
                    }
                    let sta = tx.addr1;
                    let sc = u16::from_le_bytes([fr[22], fr[23]]);
                    if self
                        .stations
                        .pending_assoc
                        .get(&sta)
                        .map(|pending| pending.sc)
                        != Some(sc)
                    {
                        continue;
                    }
                    self.stations.pending_assoc.remove(&sta);
                    let core_sta = self.ap.station_link_for_peer(&sta).unwrap_or(sta);
                    if crate::util::netlink_debug_enabled() {
                        eprintln!(
                            "netlink AP: ASSOC-RESP TX-STATUS sta={} acked={acked} sc={sc}",
                            crate::util::bytes_to_mac(&sta)
                        );
                    }
                    if acked {
                        if let Some(frame) = self.stations.held_eapol.remove(&sta) {
                            self.ap.note_eapol_transmitted(&core_sta);
                            let released = crate::ap::Outgoing {
                                frames: vec![frame],
                                to_network: Vec::new(),
                            };
                            route_outputs(
                                &mut self.io,
                                &released,
                                &mut self.stations,
                                &mut self.vlans,
                                &mut self.ap,
                                &self.topology,
                            );
                        }
                    } else if self.ap.is_associated(&core_sta) {
                        // A delayed negative status for a duplicate/stale
                        // Association Response must not tear down a station that
                        // has since proved connectivity by completing m4.
                        self.stations.held_eapol.remove(&sta);
                    } else {
                        self.stations.held_eapol.remove(&sta);
                        self.ap.note_assoc_response_not_acked(&core_sta);
                        // The cleanup worker performs PTK -> station -> VIF
                        // teardown. Keep all identifiers reserved until its
                        // generation-tagged completion is applied.
                        self.stations.begin_retirement(core_sta);
                    }
                    continue;
                }
                // DFS: radar on the operating channel — vacate within the move time.
                if parsed.genl_cmd() == Some(NL80211_CMD_RADAR_DETECT) {
                    if radar_event(&attrs) == Some(NL80211_RADAR_DETECTED) {
                        let fallback = fallback_channel(self.topology.channel);
                        eprintln!(
                        "netlink AP: RADAR DETECTED on {} MHz — vacating (DFS); restart on non-DFS channel {fallback}",
                        self.topology.frequency,
                    );
                        let seq = self.io.commands.next_seq();
                        let _ = self.io.commands.request_ack(
                            GenlMessage::new(self.io.family, NL80211_CMD_STOP_AP, 0, seq)
                                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex)),
                        );
                        return Err(io::Error::other(format!(
                        "radar detected on channel {}; vacated — restart on non-DFS channel {fallback}",
                        self.topology.channel,
                    )));
                    }
                    continue;
                }
                let (rt, kernel_management) = match parsed.genl_cmd() {
                    Some(c) if c == NL80211_CMD_FRAME => {
                        let Some(f) = msg::find_attr(&attrs, NL80211_ATTR_FRAME) else {
                            continue;
                        };
                        if self.ap.mld && crate::util::netlink_debug_enabled() {
                            let attr_summary = attrs
                                .iter()
                                .map(|(typ, data)| format!("{typ}:{}", data.len()))
                                .collect::<Vec<_>>()
                                .join(",");
                            let mac = msg::find_attr(&attrs, NL80211_ATTR_MAC)
                                .filter(|m| m.len() == 6)
                                .map(|m| {
                                    let mut a = [0u8; 6];
                                    a.copy_from_slice(m);
                                    crate::util::bytes_to_mac(&a)
                                })
                                .unwrap_or_else(|| "-".to_string());
                            let mld = msg::find_attr(&attrs, NL80211_ATTR_MLD_ADDR)
                                .filter(|m| m.len() == 6)
                                .map(|m| {
                                    let mut a = [0u8; 6];
                                    a.copy_from_slice(m);
                                    crate::util::bytes_to_mac(&a)
                                })
                                .unwrap_or_else(|| "-".to_string());
                            let link_id = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            eprintln!(
                                "netlink AP: MLD frame attrs mac={mac} mld={mld} link_id={link_id}"
                            );
                            eprintln!("netlink AP: MLD frame attr_ids={attr_summary}");
                            let head_len = f.len().min(48);
                            let mut head = String::new();
                            for b in &f[..head_len] {
                                use std::fmt::Write as _;
                                let _ = write!(&mut head, "{b:02x}");
                            }
                            eprintln!("netlink AP: MLD frame head={head}");
                        }
                        // MLD RX translation: learn which link the client is on
                        // and rewrite the target link-BSSID (addr1 RA + addr3
                        // BSSID) to the canonical `bssid` so the single-address
                        // `Ap` matches it. ath12k does not consistently attach
                        // MLO_LINK_ID to pre-association management frames, so
                        // fall back to the link BSSID and event frequency instead
                        // of silently dropping a valid Authentication request.
                        let mut fbytes = f.to_vec();
                        self.ap.set_mgmt_rx_link(None);
                        if self.ap.mld {
                            if fbytes.len() < 22 {
                                continue;
                            }
                            let reported_lid = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .copied();
                            let event_freq = msg::find_attr(&attrs, NL80211_ATTR_WIPHY_FREQ)
                                .and_then(|v| v.get(..4))
                                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
                            let mut ra = [0u8; 6];
                            ra.copy_from_slice(&fbytes[4..10]);
                            let mut frame_bssid = [0u8; 6];
                            frame_bssid.copy_from_slice(&fbytes[16..22]);
                            let Some(lid) = resolve_mld_rx_link(
                                &self.topology.links,
                                reported_lid,
                                event_freq,
                                &ra,
                                &frame_bssid,
                                &self.ap.mld_mac,
                                fbytes[0] >> 4 == dot11::SUBTYPE_PROBE_REQ,
                            ) else {
                                eprintln!(
                                "netlink AP: dropped MLD mgmt subtype={} reported_link={reported_lid:?} freq={event_freq:?} ra={} bssid={} (no matching configured link)",
                                fbytes[0] >> 4,
                                crate::util::bytes_to_mac(&ra),
                                crate::util::bytes_to_mac(&frame_bssid),
                            );
                                continue;
                            };
                            if reported_lid.is_none() {
                                eprintln!(
                                "netlink AP: inferred missing MLO_LINK_ID={} for mgmt subtype={} freq={event_freq:?} ra={}",
                                lid,
                                fbytes[0] >> 4,
                                crate::util::bytes_to_mac(&ra),
                            );
                            }
                            // The state machine builds link-addressed responses
                            // (probe responses in particular) for the link the
                            // frame arrived on.
                            self.ap.set_mgmt_rx_link(Some(lid));
                            let mut client = [0u8; 6];
                            client.copy_from_slice(&fbytes[10..16]);
                            // reference AP translates every address belonging to the
                            // peer MLD back to the association station before
                            // running its MLME. Without this, an iPhone that
                            // later uses its MLD MAC (or partner-link MAC) is
                            // mistaken for a new station and the live AP_VLAN is
                            // repeatedly destroyed and recreated.
                            let core_client =
                                self.ap.station_link_for_peer(&client).unwrap_or(client);
                            self.topology.station_links.insert(core_client, lid);
                            fbytes[10..16].copy_from_slice(&core_client);
                            fbytes[4..10].copy_from_slice(&self.bssid);
                            fbytes[16..22].copy_from_slice(&self.bssid);
                        }
                        let mut v = dot11::RADIOTAP_TX.to_vec();
                        v.extend_from_slice(&fbytes);
                        (v, true)
                    }
                    Some(c) if c == NL80211_CMD_CONTROL_PORT_FRAME => {
                        let (Some(eapol), Some(src)) = (
                            msg::find_attr(&attrs, NL80211_ATTR_FRAME),
                            msg::find_attr(&attrs, NL80211_ATTR_MAC),
                        ) else {
                            continue;
                        };
                        if src.len() != 6 {
                            continue;
                        }
                        let mut sta = [0u8; 6];
                        sta.copy_from_slice(src);
                        if self.ap.mld {
                            if let Some(link_sta) = self.ap.station_link_for_peer(&sta) {
                                sta = link_sta;
                            }
                            if let Some(&lid) = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                .and_then(|v| v.first())
                                .filter(|lid| self.topology.links.contains_key(lid))
                            {
                                self.topology.station_links.insert(sta, lid);
                            }
                        }
                        if crate::util::netlink_debug_enabled() {
                            let mut s = [0u8; 6];
                            s.copy_from_slice(src);
                            eprintln!(
                                "netlink AP: CTRL_PORT eapol src={} -> sta={} link={:?}",
                                crate::util::bytes_to_mac(&s),
                                crate::util::bytes_to_mac(&sta),
                                msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                                    .and_then(|v| v.first())
                            );
                        }
                        (reconstruct_eapol(&self.bssid, &sta, eapol), false)
                    }
                    _ => continue,
                };
                let out = if kernel_management {
                    self.ap.handle_kernel_incoming(&rt)
                } else {
                    self.ap.handle_incoming(&rt)
                };
                route_outputs(
                    &mut self.io,
                    &out,
                    &mut self.stations,
                    &mut self.vlans,
                    &mut self.ap,
                    &self.topology,
                );
            }
        }

        Ok(())
    }

    pub(super) fn release_stalled_association(&mut self) {
        // A few real drivers occasionally lose the Association Response
        // TX-status event even though the response reached the client. Holding
        // m1 forever in that case makes every core retry replace the same held
        // frame, then ends in a message-1 timeout without transmitting any of
        // them. After a bounded grace, release the newest held frame. If the
        // Association Response truly was lost, the station ignores m1 and
        // retries association; it still cannot be authorized without valid
        // m2/m4 MICs.
        let now = Instant::now();
        let stalled_assoc: Vec<[u8; 6]> = self
            .stations
            .pending_assoc
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.sent_at) >= ASSOC_TX_STATUS_GRACE)
            .map(|(sta, _)| *sta)
            .collect();
        for sta in stalled_assoc {
            self.stations.pending_assoc.remove(&sta);
            let core_sta = self.ap.station_link_for_peer(&sta).unwrap_or(sta);
            if let Some(frame) = self.stations.held_eapol.remove(&sta) {
                eprintln!(
                "netlink AP: ASSOC-RESP TX-STATUS missing for {}; releasing held EAPOL after {} ms",
                crate::util::bytes_to_mac(&sta),
                ASSOC_TX_STATUS_GRACE.as_millis(),
            );
                self.ap.note_eapol_transmitted(&core_sta);
                let released = crate::ap::Outgoing {
                    frames: vec![frame],
                    to_network: Vec::new(),
                };
                route_outputs(
                    &mut self.io,
                    &released,
                    &mut self.stations,
                    &mut self.vlans,
                    &mut self.ap,
                    &self.topology,
                );
            }
        }
    }

    pub(super) fn tick_protocol(&mut self) {
        // Handshake-reliability maintenance: retransmit pending EAPOL m1/m3
        // whose m2/m4 was lost, and deauth a station whose 4-way times out. The
        // recv() above blocks for at most 20 ms, so timer granularity stays close
        // to the reference event loop's 100-ms first EAPOL retry.
        let tick_out = self.ap.tick();
        if !tick_out.frames.is_empty() {
            route_outputs(
                &mut self.io,
                &tick_out,
                &mut self.stations,
                &mut self.vlans,
                &mut self.ap,
                &self.topology,
            );
        }
    }
}
