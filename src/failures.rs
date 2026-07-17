//! Intrusion logging: a fingerprinted, deduplicated record of failed
//! authentication and decryption attempts.
//!
//! Each failure is keyed by a client fingerprint (MAC + a hash of the client's
//! association characteristics) and a [`FailureKind`]. A bounded set of the most
//! recent *distinct* keys is kept; a repeat of an identical key bumps a counter
//! rather than consuming a slot, so a single client hammering the AP can't evict
//! the history of every other client.

/// What kind of failure was observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailureKind {
    /// WPA2/WPA3 4-way handshake message-2 MIC mismatch — a wrong PSK.
    FourWayMic,
    /// WPA3-SAE commit/confirm failure — wrong password, or a bad/forged element.
    Sae,
    /// CCMP data-frame decryption / MIC failure.
    CcmpData,
    /// Protected (PMF) management-frame decryption / AES-CMAC failure.
    ProtectedMgmt,
}

impl FailureKind {
    pub fn label(self) -> &'static str {
        match self {
            FailureKind::FourWayMic => "wrong-psk (4-way MIC)",
            FailureKind::Sae => "sae auth",
            FailureKind::CcmpData => "ccmp data MIC",
            FailureKind::ProtectedMgmt => "protected-mgmt MIC/CMAC",
        }
    }
}

/// One deduplicated entry: a (fingerprint, kind) seen `count` times.
#[derive(Clone)]
pub struct FailureRecord {
    pub mac: [u8; 6],
    /// FNV-1a hash of the client's association characteristics (0 if the client
    /// never associated, e.g. a failure during SAE authentication).
    pub traits: u64,
    pub kind: FailureKind,
    pub count: u64,
    /// Monotonic sequence numbers (not wall-clock) of the first and most recent
    /// occurrence — used for ordering and LRU eviction.
    pub first_seq: u64,
    pub last_seq: u64,
}

/// A bounded, deduplicated log of failed attempts.
pub struct FailureLog {
    records: Vec<FailureRecord>,
    cap: usize,
    seq: u64,
}

impl Default for FailureLog {
    fn default() -> FailureLog {
        FailureLog::with_capacity(25)
    }
}

impl FailureLog {
    pub fn with_capacity(cap: usize) -> FailureLog {
        FailureLog {
            records: Vec::new(),
            cap: cap.max(1),
            seq: 0,
        }
    }

    /// Record one failure and return the running count for this (mac, traits,
    /// kind). If an identical entry already exists, increment its counter;
    /// otherwise add a new entry, evicting the least-recently-seen one when full.
    pub fn record(&mut self, mac: [u8; 6], traits: u64, kind: FailureKind) -> u64 {
        self.seq += 1;
        let seq = self.seq;
        if let Some(r) = self
            .records
            .iter_mut()
            .find(|r| r.mac == mac && r.traits == traits && r.kind == kind)
        {
            r.count += 1;
            r.last_seq = seq;
            return r.count;
        }
        if self.records.len() >= self.cap {
            if let Some(i) = (0..self.records.len()).min_by_key(|&i| self.records[i].last_seq) {
                self.records.remove(i);
            }
        }
        self.records.push(FailureRecord {
            mac,
            traits,
            kind,
            count: 1,
            first_seq: seq,
            last_seq: seq,
        });
        1
    }

    /// A human-readable, most-recent-last summary of the log.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for r in self.records() {
            out.push_str(&format!(
                "  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {:<24}  x{}  (traits {:#018x})\n",
                r.mac[0],
                r.mac[1],
                r.mac[2],
                r.mac[3],
                r.mac[4],
                r.mac[5],
                r.kind.label(),
                r.count,
                r.traits,
            ));
        }
        out
    }

    /// The recorded entries, most-recently-seen last.
    pub fn records(&self) -> Vec<&FailureRecord> {
        let mut r: Vec<&FailureRecord> = self.records.iter().collect();
        r.sort_by_key(|x| x.last_seq);
        r
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// FNV-1a hash of a client's association characteristics (the IE block of its
/// (Re)Association Request), to fingerprint the client beyond its (spoofable)
/// MAC address.
pub fn client_traits(ies: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in ies {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const B: [u8; 6] = [2, 0, 0, 0, 0, 2];

    #[test]
    fn identical_failures_increment_a_counter() {
        let mut log = FailureLog::default();
        for _ in 0..10 {
            log.record(A, 0x1111, FailureKind::FourWayMic);
        }
        let recs = log.records();
        assert_eq!(recs.len(), 1, "identical attempts dedup to one entry");
        assert_eq!(recs[0].count, 10);
    }

    #[test]
    fn distinct_fingerprint_or_kind_makes_new_entries() {
        let mut log = FailureLog::default();
        log.record(A, 0x1111, FailureKind::FourWayMic);
        log.record(B, 0x1111, FailureKind::FourWayMic); // different mac
        log.record(A, 0x2222, FailureKind::FourWayMic); // different traits
        log.record(A, 0x1111, FailureKind::CcmpData); // different kind
        assert_eq!(log.records().len(), 4);
    }

    #[test]
    fn bounded_to_capacity_evicting_least_recent() {
        let mut log = FailureLog::with_capacity(25);
        // 25 distinct clients each fail once
        for i in 0..25u8 {
            log.record([2, 0, 0, 0, 0, i], 0, FailureKind::FourWayMic);
        }
        assert_eq!(log.records().len(), 25);
        // client 0 keeps failing — it stays, doesn't grow the log
        for _ in 0..5 {
            log.record([2, 0, 0, 0, 0, 0], 0, FailureKind::FourWayMic);
        }
        assert_eq!(log.records().len(), 25);
        // a 26th distinct client evicts the least-recently-seen (client 1, since
        // client 0 was just refreshed)
        log.record([2, 0, 0, 0, 0, 99], 0, FailureKind::FourWayMic);
        assert_eq!(log.records().len(), 25);
        let macs: Vec<u8> = log.records().iter().map(|r| r.mac[5]).collect();
        assert!(macs.contains(&0), "recently-active client 0 retained");
        assert!(macs.contains(&99), "new client added");
        assert!(!macs.contains(&1), "least-recently-seen client 1 evicted");
    }
}
