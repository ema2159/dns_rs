use crate::dns_protocol::dns_packet::dns_packet_err::DNSPacketErr;
use crate::dns_protocol::dns_packet::DNSPacketBuffer;

pub struct DNSDomain;

impl DNSDomain {
    /// Parse DNS domain name composed by labels starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last label.
    pub fn parse_domain(buffer: &mut DNSPacketBuffer, jump: u8) -> Result<String, DNSPacketErr> {
        const MAX_JUMPS: u8 = 5;
        if jump == MAX_JUMPS {
            return Err(DNSPacketErr::MaxJumpsErr);
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
                let reused_labels = DNSDomain::parse_domain(buffer, jump + 1)?;
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
            let label = (String::from_utf8(label_buf)
                .or_else(|_| Err(DNSPacketErr::NonUTF8LabelErr))?)
            .to_lowercase();

            // ["www"].push("google")
            labels_buf.push(label);
        }

        // ["www", "google", "com"] -> "www.google.com"
        let label_sequence = labels_buf.join(".");

        Ok(label_sequence)
    }
}
