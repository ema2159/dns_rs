mod a_record;
mod aaaa_record;
mod cname_record;
mod dname_record;
mod mx_record;
mod ns_record;
mod ptr_record;
mod soa_record;
mod srv_record;
mod txt_record;
mod unknown_record;
#[cfg(test)]
use super::PACKET_SIZE;
use super::{DNSError, DNSPacketBuffer, Domain, QueryType, HEADER_SIZE};

use enum_dispatch::enum_dispatch;

pub use a_record::A;
pub use aaaa_record::AAAA;
pub use cname_record::CNAME;
pub use dname_record::DNAME;
pub use mx_record::MX;
pub use ns_record::NS;
pub use ptr_record::PTR;
pub use soa_record::SOA;
pub use srv_record::SRV;
pub use txt_record::TXT;
pub use unknown_record::Unknown;

#[derive(Debug)]
pub struct Record {
    preamble: RecordPreamble,
    data: RecordData,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.preamble.domain == other.preamble.domain
            && self.preamble.class == other.preamble.class
            && self.preamble.ttl == other.preamble.ttl
            && self.data == other.data
    }
}

#[enum_dispatch]
#[derive(Debug, PartialEq)]
pub enum RecordData {
    A,
    AAAA,
    CNAME,
    DNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    Unknown,
}

trait RecordDataRead {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &RecordPreamble,
    ) -> Result<Self, DNSError>
    where
        Self: Sized;
}

#[enum_dispatch(RecordData)]
pub trait RecordDataWrite: std::fmt::Debug {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError>;
    fn query_type(&self) -> QueryType;
}

#[derive(Debug, PartialEq)]
pub struct RecordPreamble {
    domain: Domain,         // Variable length
    record_type: QueryType, // 2 bytes
    class: u16,             // 2 bytes
    ttl: u32,               // 4 bytes
    len: u16,               // 2 bytes
}

impl RecordPreamble {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSError> {
        Ok(RecordPreamble {
            domain: Domain::parse_domain(buffer, 0)?,
            record_type: QueryType::from_num(buffer.read_u16()?),
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        })
    }

    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(self.record_type.to_num())?; // filled by record data
        buffer.write_u16(self.class)?;
        buffer.write_u32(self.ttl)?;
        buffer.write_u16(0)?; // filled by record data

        Ok(())
    }
}

impl Record {
    pub fn new(domain: Domain, class: u16, ttl: u32, record_data: RecordData) -> Self {
        Self {
            preamble: RecordPreamble {
                domain,
                record_type: record_data.query_type(),
                class,
                ttl,
                len: 0,
            },
            data: record_data,
        }
    }

    pub(crate) fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSError> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSError::BadPointerPosition);
        }

        let preamble = RecordPreamble::parse_from_buffer(buffer)?;
        let data = match preamble.record_type {
            QueryType::A => Ok(RecordData::A(A::parse_from_buffer(buffer, &preamble)?)),
            QueryType::AAAA => Ok(RecordData::AAAA(AAAA::parse_from_buffer(
                buffer, &preamble,
            )?)),
            QueryType::CNAME => Ok(RecordData::CNAME(CNAME::parse_from_buffer(
                buffer, &preamble,
            )?)),
            QueryType::DNAME => Ok(RecordData::DNAME(DNAME::parse_from_buffer(
                buffer, &preamble,
            )?)),
            QueryType::MX => Ok(RecordData::MX(MX::parse_from_buffer(buffer, &preamble)?)),
            QueryType::NS => Ok(RecordData::NS(NS::parse_from_buffer(buffer, &preamble)?)),
            QueryType::PTR => Ok(RecordData::PTR(PTR::parse_from_buffer(buffer, &preamble)?)),
            QueryType::SOA => Ok(RecordData::SOA(SOA::parse_from_buffer(buffer, &preamble)?)),
            QueryType::SRV => Ok(RecordData::SRV(SRV::parse_from_buffer(buffer, &preamble)?)),
            QueryType::TXT => Ok(RecordData::TXT(TXT::parse_from_buffer(buffer, &preamble)?)),
            QueryType::Unknown(_) => Ok(RecordData::Unknown(Unknown::parse_from_buffer(
                buffer, &preamble,
            )?)),
            ref unimplemented_qtype => Err(DNSError::UnimplementedRecordType(
                unimplemented_qtype.clone(),
            )),
        }?;

        Ok(Self { preamble, data })
    }

    pub(crate) fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSError::BadPointerPosition);
        }
        self.preamble.write_to_buffer(buffer)?;
        self.data.write_to_buffer(buffer)?;
        Ok(())
    }
}
