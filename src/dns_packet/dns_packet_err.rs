use super::QueryType;
// use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum DNSError {
    EndOfBuffer,
    BadPointerPosition,
    UnknownResponseCode(u8),
    NonUTF8,
    MaxJumps,
    LabelTooLarge(String, usize),
    DomainNameTooLarge(String, usize),
    UnimplementedRecordType(QueryType),
    UnknownRecordWrite,
    ReservedOrUnassigned(QueryType),
}

// impl Error for DNSError {};
