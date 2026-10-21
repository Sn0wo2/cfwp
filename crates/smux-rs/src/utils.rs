pub(super) fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(super::HEADER + data.len());
    out.push(1);
    out.push(cmd);
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(data);
    out
}
