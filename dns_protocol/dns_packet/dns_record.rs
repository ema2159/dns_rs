use crate::dns_protocol::dns_packet::dns_domain::DNSDomain;
use crate::dns_protocol::dns_packet::dns_packet_err::DNSPacketErr;
use crate::dns_protocol::dns_packet::DNSPacketBuffer;

use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct DNSRecord {
    pub preamble: DNSRecordPreamble,
    pub data: DNSRecordType,
}

#[derive(Debug, PartialEq)]
pub struct DNSRecordPreamble {
    pub label_sequence: String,    // Variable length
    pub record_type: DNSQueryType, // 2 bytes
    pub class: u16,                // 2 bytes
    pub ttl: u32,                  // 4 bytes
    pub len: u16,                  // 2 bytes
}

#[derive(Debug, PartialEq)]
pub enum DNSRecordType {
    A(Ipv4Addr),
}

#[derive(Debug, PartialEq)]
pub enum DNSQueryType {
    A,
}

impl DNSQueryType {
    fn from_num(code_num: u16) -> Result<DNSQueryType, DNSPacketErr> {
        match code_num {
            1 => Ok(DNSQueryType::A),
            _ => Err(DNSPacketErr::UnknownQueryTypeErr(code_num)),
        }
    }
}

impl DNSRecord {
    fn parse_type_a(buffer: &mut DNSPacketBuffer) -> Result<DNSRecordType, DNSPacketErr> {
        Ok(DNSRecordType::A(Ipv4Addr::from(buffer.read_u32()?)))
    }

    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.pos < 12 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

        let preamble = DNSRecordPreamble {
            label_sequence: DNSDomain::parse_domain(buffer, 0)?,
            record_type: DNSQueryType::from_num(buffer.read_u16()?)?,
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        };
        let data = match preamble.record_type {
            DNSQueryType::A => Ok(DNSRecord::parse_type_a(buffer)?),
        }?;
        Ok(DNSRecord { preamble, data })
    }
}
