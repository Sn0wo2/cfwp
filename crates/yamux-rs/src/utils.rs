pub(super) fn frame(typ: u8, flags: u16, sid: u32, length: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(super::HEADER + data.len());
    out.push(0);
    out.push(typ);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    out
}
