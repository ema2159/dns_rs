#[derive(Debug)]
pub enum DNSPacketErr {
    EndOfBufferErr,
    BadPointerPositionErr,
    UnknownResponseCodeErr(u8),
    UnknownQueryTypeErr(u16),
    NonUTF8LabelErr,
    MaxJumpsErr,
    BuffWriteErr,
}
