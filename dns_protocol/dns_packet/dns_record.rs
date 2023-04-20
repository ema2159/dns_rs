mod a_record;
mod unknown_record;
use super::DNSDomain;
use super::DNSPacketBuffer;
use super::DNSPacketErr;
use super::DNSQueryType;
use super::HEADER_SIZE;
#[cfg(test)]
use super::PACKET_SIZE;

pub use a_record::A;
pub use unknown_record::Unknown;

#[derive(Debug, PartialEq)]
pub enum DNSRecord {
    A(A),
    Unknown(Unknown),
}

pub trait DNSRecordType {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr>
    where
        Self: Sized;
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr>;
}

#[derive(Debug, PartialEq)]
pub struct DNSRecordPreamble {
    pub domain: DNSDomain,         // Variable length
    pub record_type: DNSQueryType, // 2 bytes
    pub class: u16,                // 2 bytes
    pub ttl: u32,                  // 4 bytes
    pub len: u16,                  // 2 bytes
}

impl DNSRecordPreamble {
    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        Ok(DNSRecordPreamble {
            domain: DNSDomain::parse_domain(buffer, 0)?,
            record_type: DNSQueryType::from_num(buffer.read_u16()?),
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        })
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(self.record_type.to_num())?;
        buffer.write_u16(self.class)?;
        buffer.write_u32(self.ttl)?;
        buffer.write_u16(self.len)?;

        Ok(())
    }
}

impl DNSRecord {
    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let preamble = DNSRecordPreamble::parse_from_buffer(buffer)?;
        let record = match preamble.record_type {
            DNSQueryType::A => Ok(DNSRecord::A(A::parse_from_buffer(buffer, preamble)?)),
            DNSQueryType::Unknown(_) => Ok(DNSRecord::Unknown(Unknown::parse_from_buffer(
                buffer, preamble,
            )?)),
        }?;

        Ok(record)
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }
        match self {
            DNSRecord::A(record) => record.write_to_buffer(buffer)?,
            DNSRecord::Unknown(record) => record.write_to_buffer(buffer)?,
        };
        Ok(())
    }
}
