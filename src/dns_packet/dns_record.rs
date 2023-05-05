mod a_record;
mod aaaa_record;
mod soa_record;
mod unknown_record;
use super::DNSDomain;
use super::DNSPacketBuffer;
use super::DNSPacketErr;
use super::DNSQueryType;
use super::HEADER_SIZE;
#[cfg(test)]
use super::PACKET_SIZE;

use enum_dispatch::enum_dispatch;

pub use a_record::A;
pub use aaaa_record::AAAA;
pub use soa_record::SOA;
pub use unknown_record::Unknown;

#[derive(Debug, PartialEq)]
pub struct DNSRecord {
    preamble: DNSRecordPreamble,
    data: DNSRecordData,
}

#[enum_dispatch]
#[derive(Debug, PartialEq)]
pub enum DNSRecordData {
    A,
    AAAA,
    SOA,
    Unknown,
}

trait DNSRecordDataRead {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr>
    where
        Self: Sized;
}

#[enum_dispatch(DNSRecordData)]
pub trait DNSRecordDataWrite: std::fmt::Debug {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr>;
    fn query_type(&self) -> DNSQueryType;
}

#[derive(Debug, PartialEq)]
pub struct DNSRecordPreamble {
    domain: DNSDomain,         // Variable length
    record_type: DNSQueryType, // 2 bytes
    class: u16,                // 2 bytes
    ttl: u32,                  // 4 bytes
    len: u16,                  // 2 bytes
}

impl DNSRecordPreamble {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        Ok(DNSRecordPreamble {
            domain: DNSDomain::parse_domain(buffer, 0)?,
            record_type: DNSQueryType::from_num(buffer.read_u16()?),
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        })
    }

    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(0)?; // filled by record data 
        buffer.write_u16(self.class)?;
        buffer.write_u32(self.ttl)?;
        buffer.write_u16(0)?; // filled by record data

        Ok(())
    }
}

impl DNSRecord {
    pub fn new(domain: DNSDomain, class: u16, ttl: u32, record_data: DNSRecordData) -> Self {
        Self {
            preamble: DNSRecordPreamble {
                domain,
                record_type: record_data.query_type(),
                class,
                ttl,
                len: 0,
            },
            data: record_data,
        }
    }

    pub(crate) fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let preamble = DNSRecordPreamble::parse_from_buffer(buffer)?;
        let data = match preamble.record_type {
            DNSQueryType::A => Ok(DNSRecordData::A(A::parse_from_buffer(buffer, &preamble)?)),
            DNSQueryType::AAAA => Ok(DNSRecordData::AAAA(AAAA::parse_from_buffer(
                buffer, &preamble,
            )?)),
            DNSQueryType::SOA => Ok(DNSRecordData::SOA(SOA::parse_from_buffer(
                buffer, &preamble,
            )?)),
            DNSQueryType::Unknown(_) => Ok(DNSRecordData::Unknown(Unknown::parse_from_buffer(
                buffer, &preamble,
            )?)),
            ref unimplemented_qtype => Err(DNSPacketErr::UnimplementedRecordType(
                unimplemented_qtype.clone(),
            )),
        }?;

        Ok(Self { preamble, data })
    }

    pub(crate) fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }
        self.preamble.write_to_buffer(buffer)?;
        self.data.write_to_buffer(buffer)?;
        Ok(())
    }
}
