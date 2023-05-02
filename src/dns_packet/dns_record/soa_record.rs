use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};

#[derive(Debug, PartialEq)]
pub struct SOA {
    pub domain: DNSDomain,
    pub mname: DNSDomain,
    pub rname: DNSDomain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minttl: u32,
    pub ttl: u32,
}

impl DNSRecordType for SOA {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        Ok(SOA {
            domain: preamble.domain,
            mname: DNSDomain::parse_domain(buffer, 0)?,
            rname: DNSDomain::parse_domain(buffer, 0)?,
            serial: buffer.read_u32()?,
            refresh: buffer.read_u32()?,
            retry: buffer.read_u32()?,
            expire: buffer.read_u32()?,
            minttl: buffer.read_u32()?,
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        const RECORD_TYPE: u16 = 6;
        const CLASS: u16 = 1;
        const LEN: u16 = 4;
        unimplemented!();
    }
}
