use super::QueryType;
use std::error::Error;
use std::fmt;

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

impl fmt::Display for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err_msg = match self {
            Self::EndOfBuffer => "pointer of buffer is out of bounds".to_string(),
            Self::BadPointerPosition => {
                "DNS section is being accessed at the wrong position".to_string()
            }
            Self::UnknownResponseCode(code) => format!("wrong response code {}", code),
            Self::NonUTF8 => "encountered non UTF-8 sequence".to_string(),
            Self::MaxJumps => {
                "exceeded max amount of jumps when processing compressed DNS label sequence"
                    .to_string()
            }
            Self::LabelTooLarge(label, size) => format!(
                "label {} of size {} exceeds maximum label length",
                label, size
            ),
            Self::DomainNameTooLarge(domain, size) => format!(
                "label {} of size {} exceeds maximum label length",
                domain, size
            ),
            Self::UnimplementedRecordType(rtype) => {
                format!("record of type {:?} has not been implemented", rtype)
            }
            Self::UnknownRecordWrite => "cannot write record of unknown type".to_string(),
            Self::ReservedOrUnassigned(qtype) => {
                format!("tried to write record of type {:?} containing fields which are currently reserved or unassigned", qtype)
            }
        };
        write!(f, "{}", err_msg)
    }
}

impl Error for DNSError {}
