use super::DNSDomain;
use super::DNSPacketBuffer;
use super::DNSPacketErr;
use super::DNSQueryType;
use super::HEADER_SIZE;
#[cfg(test)]
use super::PACKET_SIZE;

#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    pub domain: DNSDomain,         // Variable length
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
            domain: label_sequence,
            record_type,
            class,
        })
    }

    fn write_to_buffer(self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(self.record_type.to_num())?;
        buffer.write_u16(self.class)?;
        Ok(())
    }
}
