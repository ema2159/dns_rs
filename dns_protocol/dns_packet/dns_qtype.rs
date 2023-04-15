#[derive(Debug, PartialEq)]
pub enum DNSQueryType {
    A,
    Unknown(u16),
}

impl DNSQueryType {
    pub fn from_num(code_num: u16) -> DNSQueryType {
        match code_num {
            1 => DNSQueryType::A,
            _ => DNSQueryType::Unknown(code_num),
        }
    }
}
