pub(super) fn end_frame(sid: u32, error: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&4_u16.to_be_bytes());
    let [_, _, sid_0, sid_1] = sid.to_be_bytes();
    out.extend_from_slice(&[sid_0, sid_1]);
    out.push(super::END);
    out.push(if error { super::OPTION_ERROR } else { 0 });
    out
}
