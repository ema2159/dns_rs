use super::QueryType;
// use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum DNSError {
    EndOfBuffer,
    BadPointerPosition,
    UnknownResponseCode(u8),
    NonUTF8,
    MaxJumps,
    BuffWrite,
    LabelTooLarge(String, usize),
    DomainNameTooLarge(String, usize),
    UnimplementedRecordType(QueryType),
    UnknownRecord,
    Unassigned,
}

// impl Error for DNSError {};
