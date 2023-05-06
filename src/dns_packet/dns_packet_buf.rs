use std::collections::BTreeMap;

use super::DNSPacketErr;
use super::PACKET_SIZE;

#[derive(Debug, PartialEq)]
pub struct DNSPacketBuffer {
    data: [u8; PACKET_SIZE],
    pos: usize,
    labels_lookup: BTreeMap<String, u16>,
}

impl DNSPacketBuffer {
    /// Initializes DNS packet buffer with the given data and its position pointer set to 0.
    pub fn new(data: &[u8]) -> Self {
        let mut buf_data: [u8; PACKET_SIZE] = [0; PACKET_SIZE];
        buf_data[0..data.len()].clone_from_slice(data);

        DNSPacketBuffer {
            data: buf_data,
            pos: 0,
            labels_lookup: BTreeMap::<String, u16>::new(),
        }
    }

    /// Get current buffer pointer position
    pub(crate) fn get_pos(&self) -> usize {
        self.pos
    }

    /// Set the buffer's position pointer to a given position.
    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Move buffer's position pointer forward a number of steps.
    pub(crate) fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    // NOTE: Reading methods

    /// Return reference to data array.
    pub fn get_data(&self) -> &[u8] {
        &self.data[0..self.pos]
    }

    /// Read byte at current position. Don't move position pointer.
    pub(crate) fn get_u8(&self) -> Result<u8, DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBuffer);
        }
        let res = self.data[self.pos];

        Ok(res)
    }

    /// Read byte at current position and advance position pointer.
    pub(crate) fn read_u8(&mut self) -> Result<u8, DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBuffer);
        }
        let res = self.data[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Read two bytes at current position and advance position pointer.
    pub(crate) fn read_u16(&mut self) -> Result<u16, DNSPacketErr> {
        let high = (self.read_u8()? as u16) << 8;
        let low = self.read_u8()? as u16;

        Ok(high | low)
    }

    /// Read four bytes at current position and advance position pointer.
    pub(crate) fn read_u32(&mut self) -> Result<u32, DNSPacketErr> {
        let first_byte = (self.read_u8()? as u32) << 24;
        let second_byte = (self.read_u8()? as u32) << 16;
        let third_byte = (self.read_u8()? as u32) << 8;
        let fourth_byte = self.read_u8()? as u32;

        Ok(first_byte | second_byte | third_byte | fourth_byte)
    }

    // NOTE: Writing methods

    /// Write byte at current position and advance position pointer.
    pub(crate) fn write_u8(&mut self, val: u8) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBuffer);
        }

        self.data[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    /// Write two bytes at current position and advance position pointer.
    pub(crate) fn write_u16(&mut self, val: u16) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBuffer);
        }

        let first_byte = (val >> 8) as u8;
        let second_byte = (val & 0x00FF) as u8;

        self.write_u8(first_byte)?;
        self.write_u8(second_byte)?;

        Ok(())
    }

    /// Write four bytes at current position and advance position pointer.
    pub(crate) fn write_u32(&mut self, val: u32) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBuffer);
        }

        let first_byte = ((val >> 24) & 0x000000FF) as u8;
        let second_byte = ((val >> 16) & 0x000000FF) as u8;
        let third_byte = ((val >> 8) & 0x000000FF) as u8;
        let fourth_byte = (val & 0x000000FF) as u8;

        self.write_u8(first_byte)?;
        self.write_u8(second_byte)?;
        self.write_u8(third_byte)?;
        self.write_u8(fourth_byte)?;

        Ok(())
    }

    /// Writes two bytes at specified position. Keep position pointer in place.
    pub(crate) fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), DNSPacketErr> {
        let curr_pos = self.get_pos();
        self.seek(pos);
        self.write_u16(val)?;
        self.seek(curr_pos);
        Ok(())
    }

    // NOTE: Label caching for DNS compression

    /// Insert label sequence into buffer lookup cache.
    pub(crate) fn cache_sequence(&mut self, label: &str, pos: u16) {
        self.labels_lookup.insert(label.to_owned(), pos);
    }

    /// If label sequence exists in the lookup, return its position in the buffer, else return None.
    pub(crate) fn sequence_check_cached(&self, label: &str) -> Option<u16> {
        self.labels_lookup.get(label).copied()
    }
}
