use super::DNSDomain;
use super::DNSPacketBuffer;
use super::DNSPacketErr;
use super::HEADER_SIZE;
use super::DNSQueryType;

#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    pub label_sequence: DNSDomain, // Variable length
    pub record_type: DNSQueryType, // 2 bytes
    pub class: u16,                // 2 bytes
}

impl DNSQuestion {
    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let label_sequence = DNSDomain::parse_domain(buffer, 0)?;
        let record_type = DNSQueryType::from_num(buffer.read_u16()?);
        let class = buffer.read_u16()?;
        Ok(DNSQuestion {
            label_sequence,
            record_type,
            class,
        })
    }
}
