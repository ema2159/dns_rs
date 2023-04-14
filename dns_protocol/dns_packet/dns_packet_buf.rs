use super::DNSPacketErr;
use super::PACKET_SIZE;

#[derive(Debug, PartialEq)]
pub struct DNSPacketBuffer {
    data: [u8; PACKET_SIZE],
    pos: usize,
}

impl DNSPacketBuffer {
    /// Initializes DNS packet buffer with the given data and its position pointer set to 0.
    pub fn new(data: [u8; PACKET_SIZE]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    pub fn get_pos(&self) -> usize {
        self.pos
    }

    /// Set the buffer's position pointer to a given position.
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Move buffer's position pointer forward a number of steps.
    pub fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    // NOTE: Reading methods

    /// Read byte at current position. Don't move position pointer.
    pub fn get_u8(&self) -> Result<u8, DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBufferErr);
        }
        let res = self.data[self.pos];

        Ok(res)
    }

    /// Read byte at current position and advance position pointer.
    pub fn read_u8(&mut self) -> Result<u8, DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBufferErr);
        }
        let res = self.data[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Read two bytes at current position and advance position pointer.
    pub fn read_u16(&mut self) -> Result<u16, DNSPacketErr> {
        let high = (self.read_u8()? as u16) << 8;
        let low = self.read_u8()? as u16;

        Ok(high | low)
    }

    /// Read four bytes at current position and advance position pointer.
    pub fn read_u32(&mut self) -> Result<u32, DNSPacketErr> {
        let first_byte = (self.read_u8()? as u32) << 24;
        let second_byte = (self.read_u8()? as u32) << 16;
        let third_byte = (self.read_u8()? as u32) << 8;
        let fourth_byte = self.read_u8()? as u32;

        Ok(first_byte | second_byte | third_byte | fourth_byte)
    }

    // NOTE: Writing methods

    /// Write byte at current position and advance position pointer.
    pub fn write_u8(&mut self, val: u8) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBufferErr);
        }

        self.data[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    /// Write two bytes at current position and advance position pointer.
    pub fn write_u16(&mut self, val: u16) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBufferErr);
        }

        let first_byte = (val >> 8) as u8;
        let second_byte = (val & 0x00FF) as u8;

        self.write_u8(first_byte)?;
        self.write_u8(second_byte)?;

        Ok(())
    }

    /// Write four bytes at current position and advance position pointer.
    pub fn write_u32(&mut self, val: u32) -> Result<(), DNSPacketErr> {
        if self.pos >= PACKET_SIZE {
            return Err(DNSPacketErr::EndOfBufferErr);
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
}
