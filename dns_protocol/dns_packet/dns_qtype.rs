use super::DNSPacketErr;

#[derive(Debug, PartialEq)]
pub enum DNSQueryType {
    A,
    UNKNOWN(u16),
}

impl DNSQueryType {
    pub fn from_num(code_num: u16) -> DNSQueryType {
        match code_num {
            1 => DNSQueryType::A,
            _ => DNSQueryType::UNKNOWN(code_num),
        }
    }
}
