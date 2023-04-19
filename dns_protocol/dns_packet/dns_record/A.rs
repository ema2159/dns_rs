use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct ARecord {
    domain: DNSDomain,
    addr: Ipv4Addr,
    ttl: u32,
}

impl DNSRecordType for ARecord {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let preamble = DNSRecordPreamble::parse_from_buffer(buffer)?;
        Ok(ARecord {
            domain: preamble.domain,
            addr: Ipv4Addr::from(buffer.read_u32()?),
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        const RECORD_TYPE: u16 = 1;
        const CLASS: u16 = 1;
        const LEN: u16 = 4;
        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(RECORD_TYPE)?;
        buffer.write_u16(CLASS)?;
        buffer.write_u32(self.ttl)?;
        buffer.write_u16(LEN)?;

        for octet in self.addr.octets() {
            buffer.write_u8(octet)?;
        }

        Ok(())
    }
}
