use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};

#[derive(Debug, PartialEq)]
pub struct Unknown {
    pub domain: DNSDomain,
    pub record_type: u16,
    pub data_len: u16,
    pub ttl: u32,
}

impl DNSRecordType for Unknown {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        // Skip reading package
        buffer.step(preamble.len as usize);

        let record_type_num = preamble.record_type.to_num();

        Ok(Unknown {
            domain: preamble.domain,
            record_type: record_type_num,
            data_len: preamble.len,
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(self, _buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        Err(DNSPacketErr::UnknownRecordSend)
    }
}
