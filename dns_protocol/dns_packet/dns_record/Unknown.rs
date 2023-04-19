use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordPreamble, DNSRecordType,
    HEADER_SIZE,
};

#[derive(Debug, PartialEq)]
pub struct UnknownRecord {
    domain: DNSDomain,
    record_type: u16,
    data_len: u16,
    ttl: u32,
}

impl DNSRecordType for UnknownRecord {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let preamble = DNSRecordPreamble::parse_from_buffer(buffer)?;
        // Skip reading package
        buffer.step(preamble.len as usize);

        let DNSQueryType::Unknown(record_type_num) = preamble.record_type;

        Ok(UnknownRecord {
            domain: preamble.domain,
            record_type: record_type_num,
            data_len: preamble.len,
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        Err(DNSPacketErr::UnknownRecordSend)
    }
}
