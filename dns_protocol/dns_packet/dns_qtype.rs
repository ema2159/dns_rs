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

    pub fn to_num(&self) -> u16 {
        match self {
            DNSQueryType::A => 1,
            DNSQueryType::Unknown(code) => *code,
        }
    }
}
