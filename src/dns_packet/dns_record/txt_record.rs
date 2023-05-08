use super::{
    DNSError, DNSPacketBuffer, QueryType, RecordDataRead, RecordDataWrite, RecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct TXT {
    pub txt_data: String,
}

impl RecordDataRead for TXT {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &RecordPreamble,
    ) -> Result<Self, DNSError> {
        let curr_pos = buffer.get_pos();
        let txt_slice = &buffer.get_data()[curr_pos..curr_pos + preamble.len as usize];
        let txt_str = String::from_utf8(txt_slice.to_vec()).map_err(|_| DNSError::NonUTF8Label)?;

        buffer.step(preamble.len as usize);

        Ok(TXT { txt_data: txt_str })
    }
}

impl RecordDataWrite for TXT {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        for b in self.txt_data.as_bytes() {
            buffer.write_u8(*b)?;
        }
        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> QueryType {
        QueryType::TXT
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_txt() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x31, 0x54, 0x68, 0x69,
            0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x61, 0x77, 0x65, 0x73, 0x6F, 0x6D,
            0x65, 0x20, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x21, 0x20, 0x44, 0x65, 0x66, 0x69,
            0x6E, 0x69, 0x74, 0x65, 0x6C, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x20, 0x73, 0x70, 0x61,
            0x6D, 0x6D, 0x79, 0x2E,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            254,
            RecordData::TXT(TXT {
                txt_data: "This is an awesome domain! Definitely not spammy.".to_string(),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 49);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_txt() {
        let a_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            254,
            RecordData::TXT(TXT {
                txt_data: "This is an awesome domain! Definitely not spammy.".to_string(),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        a_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x31, 0x54, 0x68, 0x69,
            0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x61, 0x77, 0x65, 0x73, 0x6F, 0x6D,
            0x65, 0x20, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x21, 0x20, 0x44, 0x65, 0x66, 0x69,
            0x6E, 0x69, 0x74, 0x65, 0x6C, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x20, 0x73, 0x70, 0x61,
            0x6D, 0x6D, 0x79, 0x2E,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
