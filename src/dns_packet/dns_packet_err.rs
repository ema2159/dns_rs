// use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum DNSPacketErr {
    EndOfBuffer,
    BadPointerPosition,
    UnknownResponseCode(u8),
    UnknownQueryType(u16),
    NonUTF8Label,
    MaxJumps,
    BuffWrite,
    LabelTooLarge(String, usize),
    DomainNameTooLarge(String, usize),
    UnimplementedRecordType,
    UnknownRecord,
}

// impl Error for DNSPacketErr {};
