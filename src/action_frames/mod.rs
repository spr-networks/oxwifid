//! Action-frame construction and protocol-specific bodies.

pub mod radio_measurement;
pub mod sa_query;
pub mod twt;
pub mod wnm;

/// Build an unprotected management Action frame carrying `body`.
pub fn build_action_frame(
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sc: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + body.len());
    frame.push((crate::frames::SUBTYPE_ACTION << 4) | (crate::frames::TYPE_MGMT << 2));
    frame.push(0);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(a1);
    frame.extend_from_slice(a2);
    frame.extend_from_slice(a3);
    frame.extend_from_slice(&sc.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

pub use crate::frames::SUBTYPE_ACTION;
