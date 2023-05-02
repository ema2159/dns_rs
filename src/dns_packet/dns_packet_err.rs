use super::DNSQueryType;
// use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum DNSPacketErr {
    EndOfBuffer,
    BadPointerPosition,
    UnknownResponseCode(u8),
    NonUTF8Label,
    MaxJumps,
    BuffWrite,
    LabelTooLarge(String, usize),
    DomainNameTooLarge(String, usize),
    UnimplementedRecordType(DNSQueryType),
    UnknownRecord,
}

// impl Error for DNSPacketErr {};
