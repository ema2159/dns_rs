use super::DNSPacketErr;

#[derive(Debug, PartialEq)]
pub enum DNSQueryType {
    A,
    UNKNOWN(u16),
}

impl DNSQueryType {
    pub fn from_num(code_num: u16) -> Result<DNSQueryType, DNSPacketErr> {
        match code_num {
            1 => Ok(DNSQueryType::A),
            _ => Ok(DNSQueryType::UNKNOWN(code_num)),
        }
    }
}
