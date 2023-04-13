use crate::dns_protocol::dns_packet::dns_domain::DNSDomain;
use crate::dns_protocol::dns_packet::dns_packet_err::DNSPacketErr;
use crate::dns_protocol::dns_packet::DNSPacketBuffer;

use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub enum DNSRecord {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    UNKNOWN {
        domain: String,
        record_type: u16,
        data_len: u16,
        ttl: u32,
    },
}

#[derive(Debug, PartialEq)]
pub struct DNSRecordPreamble {
    pub domain: String,            // Variable length
    pub record_type: DNSQueryType, // 2 bytes
    pub class: u16,                // 2 bytes
    pub ttl: u32,                  // 4 bytes
    pub len: u16,                  // 2 bytes
}

#[derive(Debug, PartialEq)]
pub enum DNSQueryType {
    A,
    UNKNOWN(u16),
}

impl DNSQueryType {
    fn from_num(code_num: u16) -> Result<DNSQueryType, DNSPacketErr> {
        match code_num {
            1 => Ok(DNSQueryType::A),
            _ => Ok(DNSQueryType::UNKNOWN(code_num)),
        }
    }
}

impl DNSRecord {
    fn parse_type_a(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<DNSRecord, DNSPacketErr> {
        Ok(DNSRecord::A {
            domain: preamble.domain,
            addr: Ipv4Addr::from(buffer.read_u32()?),
            ttl: preamble.ttl,
        })
    }

    fn parse_type_unknown(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<DNSRecord, DNSPacketErr> {
        let DNSQueryType::UNKNOWN(record_type_num) = preamble.record_type
            else {
                unreachable!()
            };
        // Skip reading package
        buffer.step(preamble.len as usize);

        Ok(DNSRecord::UNKNOWN {
            domain: preamble.domain,
            record_type: record_type_num,
            data_len: preamble.len,
            ttl: preamble.ttl,
        })
    }

    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.pos < 12 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

        let preamble = DNSRecordPreamble {
            domain: DNSDomain::parse_domain(buffer, 0)?,
            record_type: DNSQueryType::from_num(buffer.read_u16()?)?,
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        };
        let record = match preamble.record_type {
            DNSQueryType::A => Ok(DNSRecord::parse_type_a(buffer, preamble)?),
            DNSQueryType::UNKNOWN(_) => Ok(DNSRecord::parse_type_unknown(buffer, preamble)?),
        }?;

        Ok(record)
    }
}