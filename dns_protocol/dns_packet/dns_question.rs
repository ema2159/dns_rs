use crate::dns_protocol::dns_packet::dns_domain::DNSDomain;
use crate::dns_protocol::dns_packet::dns_packet_err::DNSPacketErr;
use crate::dns_protocol::dns_packet::DNSPacketBuffer;

#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    pub label_sequence: String, // Variable length
    pub record_type: u16,       // 2 bytes
    pub class: u16,             // 2 bytes
}

impl DNSQuestion {
    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < 12 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

        let label_sequence = DNSDomain::parse_domain(buffer, 0)?;
        let record_type = buffer.read_u16()?;
        let class = buffer.read_u16()?;
        Ok(DNSQuestion {
            label_sequence,
            record_type,
            class,
        })
    }
}
