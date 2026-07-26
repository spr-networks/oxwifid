//! Common wire-format structures.

use crate::frames::{ETHERTYPE_EAPOL, FC_FROMDS, FC_PROTECTED, FC_TODS, TYPE_DATA};

/// PHY generation advertised in beacons and association responses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PhyMode {
    Ht,
    Vht,
    He,
    Eht,
}

/// Capability-element payloads reported by the radio for one frequency band.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct PhyCapabilities {
    pub ht: Option<Vec<u8>>,
    pub vht: Option<Vec<u8>>,
    pub he: Option<Vec<u8>>,
    pub eht: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthBody<'a> {
    pub algo: u16,
    pub seq: u16,
    pub status: u16,
    pub payload: &'a [u8],
}

/// A malformed or ambiguous information-element stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IeParseError;

/// A parsed 802.11 frame with its variable MAC header consumed.
#[derive(Debug, Clone)]
pub struct Dot11 {
    pub fc0: u8,
    pub fc1: u8,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub sc: u16,
    pub qos: Option<u16>,
    pub body: Vec<u8>,
}

impl Dot11 {
    pub fn frame_type(&self) -> u8 {
        (self.fc0 >> 2) & 0x3
    }
    pub fn subtype(&self) -> u8 {
        (self.fc0 >> 4) & 0xF
    }
    pub fn to_ds(&self) -> bool {
        self.fc1 & FC_TODS != 0
    }
    pub fn from_ds(&self) -> bool {
        self.fc1 & FC_FROMDS != 0
    }
    pub fn protected(&self) -> bool {
        self.fc1 & FC_PROTECTED != 0
    }

    /// Parse an 802.11 frame (no radiotap).
    pub fn parse(buf: &[u8]) -> Option<Dot11> {
        if buf.len() < 24 {
            return None;
        }
        let fc0 = buf[0];
        let fc1 = buf[1];
        let frame_type = (fc0 >> 2) & 0x3;
        let subtype = (fc0 >> 4) & 0xF;
        let mut a1 = [0u8; 6];
        let mut a2 = [0u8; 6];
        let mut a3 = [0u8; 6];
        a1.copy_from_slice(&buf[4..10]);
        a2.copy_from_slice(&buf[10..16]);
        a3.copy_from_slice(&buf[16..22]);
        let sc = u16::from_le_bytes([buf[22], buf[23]]);

        let mut off = 24;
        // 4th address only present for WDS (to-DS and from-DS both set)
        if fc1 & FC_TODS != 0 && fc1 & FC_FROMDS != 0 {
            off += 6;
        }
        // QoS control for QoS data subtypes (subtype bit 0x08 of a data frame)
        let mut qos = None;
        if frame_type == TYPE_DATA && subtype & 0x08 != 0 {
            if buf.len() < off + 2 {
                return None;
            }
            qos = Some(u16::from_le_bytes([buf[off], buf[off + 1]]));
            off += 2;
        }
        if buf.len() < off {
            return None;
        }
        Some(Dot11 {
            fc0,
            fc1,
            addr1: a1,
            addr2: a2,
            addr3: a3,
            sc,
            qos,
            body: buf[off..].to_vec(),
        })
    }

    /// QoS priority/TID (`dot11_get_priority`): 0 when not a QoS frame.
    pub fn priority(&self) -> u16 {
        self.qos.map(|q| q & 0x000F).unwrap_or(0)
    }

    /// `true` if the QoS Control A-MSDU-Present bit (bit 7) is set, i.e. the
    /// payload is an aggregated A-MSDU subframe list rather than a single MSDU.
    pub fn is_amsdu(&self) -> bool {
        self.qos.map(|q| q & 0x0080 != 0).unwrap_or(false)
    }

    /// `true` if this is a fragment: the More-Fragments bit is set, or the
    /// Fragment Number (low 4 bits of the Sequence Control) is non-zero.
    pub fn is_fragment(&self) -> bool {
        (self.fc1 & 0x04) != 0 || (self.sc & 0x000F) != 0
    }

    /// `true` if this is an EAPOL frame: an unprotected Data frame whose payload
    /// is LLC/SNAP with ethertype 0x888E.
    ///
    /// Only Data frames carry an LLC/SNAP payload, so the frame type belongs in
    /// the test — otherwise the SNAP header and an EAPOL-Key body placed in a
    /// Management frame's body are parsed as a key message on the uncontrolled
    /// port. The Protected check is redundant defence rather than a fix for a
    /// reachable case (a CCMP header always sets ext_iv, so its fourth octet is
    /// never the 0x00 the SNAP match requires); it states the invariant that a
    /// protected payload is ciphertext, and lets each receiver order its
    /// protected-data and EAPOL branches freely.
    pub fn is_eapol(&self) -> bool {
        self.frame_type() == TYPE_DATA
            && !self.protected()
            && self.body.len() >= 8
            && self.body[..6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]
            && self.body[6..8] == ETHERTYPE_EAPOL.to_be_bytes()
    }

    /// The whole EAPOL frame (4-byte EAPOL header + body, after LLC/SNAP). This
    /// is what the MIC is computed over.
    pub fn eapol_frame(&self) -> Option<&[u8]> {
        if !self.is_eapol() || self.body.len() < 12 {
            return None;
        }
        let declared = u16::from_be_bytes([self.body[10], self.body[11]]) as usize;
        let end = 12usize.checked_add(declared)?;
        if end > self.body.len() {
            return None;
        }
        // Ignore link-layer padding after the declared EAPOL payload. The MIC
        // covers only the EAPOL header and its declared body.
        Some(&self.body[8..end])
    }

    /// The EAPOL-Key body, after the 4-byte EAPOL header (== `EAPOL.payload.load`).
    pub fn eapol_key_body(&self) -> Option<&[u8]> {
        let eapol = self.eapol_frame()?;
        if eapol.get(1) != Some(&3) {
            return None;
        }
        eapol.get(4..)
    }

    /// Reconstruct the integer PN from a CCMP-protected data frame body.
    pub fn ccmp_pn(&self) -> Option<u64> {
        if self.body.len() < 8 {
            return None;
        }
        let b = &self.body;
        // PN0 PN1 _ _ PN2 PN3 PN4 PN5
        let pn = (b[0] as u64)
            | ((b[1] as u64) << 8)
            | ((b[7] as u64) << 16)
            | ((b[6] as u64) << 24)
            | ((b[5] as u64) << 32)
            | ((b[4] as u64) << 40);
        Some(pn)
    }

    /// CCMP key id (bits 6-7 of the flags byte).
    pub fn ccmp_key_id(&self) -> u8 {
        if self.body.len() < 4 {
            0
        } else {
            (self.body[3] >> 6) & 0x3
        }
    }

    /// The CCMP data (ciphertext + 8-byte tag), after the 8-byte CCMP header.
    pub fn ccmp_data(&self) -> Option<&[u8]> {
        if self.body.len() < 8 {
            None
        } else {
            Some(&self.body[8..])
        }
    }
}
