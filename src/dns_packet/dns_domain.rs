use super::DNSError;
use super::DNSPacketBuffer;

#[derive(Debug)]
pub struct Domain(pub String);

impl PartialEq for Domain {
    fn eq(&self, other: &Self) -> bool {
        let (Domain(self_str), Domain(other_str)) = (self, other);

        self_str.split(&['.', '@']).collect::<Vec<_>>()
            == other_str.split(&['.', '@']).collect::<Vec<_>>()
    }
}

impl Domain {
    /// Parse DNS domain name composed by labels starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last label.
    pub(crate) fn parse_domain(buffer: &mut DNSPacketBuffer, jump: u8) -> Result<Domain, DNSError> {
        const MAX_JUMPS: u8 = 5;
        if jump == MAX_JUMPS {
            return Err(DNSError::MaxJumps);
        }

        let mut labels_buf = Vec::<String>::new();

        // Parse each label until a 0 label_size byte is encountered or until a label jump found
        loop {
            let jump_or_len_byte = buffer.get_u8()?;

            // If two MSBs are 1, mask with 0xC000 and jump to that position to reuse a previous label,
            // then jump back
            if 0b1100_0000 & jump_or_len_byte == 0b1100_0000 {
                let next_pos = buffer.get_pos() + 2;
                let jump_pos = buffer.read_u16()? ^ 0b1100_0000_0000_0000;
                buffer.seek(jump_pos as usize);
                let Domain(reused_labels) = Domain::parse_domain(buffer, jump + 1)?;
                labels_buf.push(reused_labels);
                buffer.seek(next_pos);
                break;
            }

            // If byte didn't indicate jump, then it indicates the label size
            let label_size = buffer.read_u8()?;

            // 0 size byte, finish parsing labels
            if label_size == 0 {
                break;
            }

            let mut label_buf = Vec::<u8>::new();

            // [b'g', b'o', b'o', b'g', b'l', b'e']
            for _ in 0..label_size {
                label_buf.push(buffer.read_u8()?);
            }

            // [b'g', b'o', b'o', b'g', b'l', b'e'] -> "google"
            let label =
                (String::from_utf8(label_buf).map_err(|_| DNSError::NonUTF8)?).to_lowercase();

            // ["google"].push("com")
            labels_buf.push(label);
        }

        // [google", "com"] -> "google.com"
        let label_sequence = labels_buf.join(".");

        Ok(Domain(label_sequence))
    }

    pub(crate) fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        const MAX_LABEL_SIZE: usize = 63;
        const MAX_DOMAIN_SIZE: usize = 253;

        let Domain(domain_string) = self;

        if domain_string.len() > MAX_DOMAIN_SIZE {
            return Err(DNSError::DomainNameTooLarge(
                domain_string.clone(),
                domain_string.len(),
            ));
        }

        let labels_vec: Vec<&str> = domain_string.split(&['.', '@']).collect();

        let mut jumped = false;

        for (i, label) in labels_vec.iter().enumerate() {
            let sequence_section = labels_vec[i..].join(".");
            // Check if section of label sequence is cached. If it is, use it for DNS compression.
            if let Some(cached_pos) = buffer.sequence_check_cached(&sequence_section) {
                buffer.write_u16(cached_pos | 0xC000)?;
                jumped = true;
                break;
            }

            if label.len() > MAX_LABEL_SIZE {
                return Err(DNSError::LabelTooLarge(label.to_string(), label.len()));
            }

            // If label sequence is not cached, cache it and write it to buffer.
            buffer.cache_sequence(&sequence_section, buffer.get_pos() as u16);
            buffer.write_u8(label.len() as u8)?;
            for b in label.as_bytes() {
                buffer.write_u8(*b)?;
            }
        }

        if !jumped {
            buffer.write_u8(0x00)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain() {
        let domain_data = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&domain_data);

        let parsed_domain = Domain::parse_domain(&mut dns_packet_buffer, 0).unwrap();

        let expected_domain = Domain("google.com".to_string());
        assert_eq!(parsed_domain, expected_domain);
    }

    #[test]
    fn test_jump_err() {
        let domain_data = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01, 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04,
            0xd8, 0x3a, 0xd3, 0x8e,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&domain_data);

        let parsed_domain1 = Domain::parse_domain(&mut dns_packet_buffer, 0);
        dns_packet_buffer.step(4); // Skip rest of the record information. Jump to next domain
        let parsed_domain2 = Domain::parse_domain(&mut dns_packet_buffer, 0);

        let expected_domain1 = Ok(Domain("google.com".to_string()));
        let expected_domain2 = Err(DNSError::MaxJumps);

        assert_eq!(parsed_domain1, expected_domain1);
        assert_eq!(parsed_domain2, expected_domain2);
    }

    #[test]
    fn test_write_to_buffer() {
        let domain = Domain("api.youtube.com".to_string());
        let mut buffer = DNSPacketBuffer::new(&[]);
        domain.write_to_buffer(&mut buffer).unwrap();

        let expected_domain_bytes = [
            0x03, 0x61, 0x70, 0x69, 0x07, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_domain_bytes);
        expected_buffer.seek(expected_domain_bytes.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }

    #[test]
    fn test_write_compression() {
        let domain0 = Domain("api.youtube.com".to_string());
        let domain1 = Domain("dev.youtube.com".to_string());
        let mut buffer = DNSPacketBuffer::new(&[]);
        domain0.write_to_buffer(&mut buffer).unwrap();
        domain1.write_to_buffer(&mut buffer).unwrap();

        let expected_domain_bytes = [
            0x03, 0x61, 0x70, 0x69, 0x07, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x03, 0x64, 0x65, 0x76, 0xC0, 0x04,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_domain_bytes);
        expected_buffer.seek(expected_domain_bytes.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }

    #[test]
    fn test_label_too_large() {
        let large_label =
            "apigodanfpandsadkjsabdjkasdjasjdnapfnapifamnfpkamnfpkanfpanspfasfpsanfpa".to_string();
        let domain = Domain(large_label.clone());
        let mut buffer = DNSPacketBuffer::new(&[]);
        let res = domain.write_to_buffer(&mut buffer);

        let expected = Err(DNSError::LabelTooLarge(
            large_label.clone(),
            large_label.len(),
        ));

        assert_eq!(res, expected)
    }

    #[test]
    fn test_domain_too_large() {
        let super_long_domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string();
        let domain = Domain(super_long_domain.clone());
        let mut buffer = DNSPacketBuffer::new(&[]);
        let res = domain.write_to_buffer(&mut buffer);

        let expected = Err(DNSError::DomainNameTooLarge(
            super_long_domain.clone(),
            super_long_domain.len(),
        ));

        assert_eq!(res, expected)
    }
}
