//! Shared protocol codec for the Pocket Relay tunnel protocol

#![warn(missing_docs, unused_variables, unused_crate_dependencies)]

use thiserror::Error;

/// Current version of the protocol
pub const VERSION: u8 = 1;

/// Individual tunnel message packet, includes the packet header
/// and the message
#[derive(Debug)]
pub struct TunnelPacket {
    /// Packet header
    pub header: TunnelMessageHeader,
    /// Packet body
    pub message: TunnelMessage,
}

impl TunnelPacket {
    /// Reads a tunnel packet from the provided deserializer
    pub fn read(read: &mut MessageDeserializer<'_>) -> Result<TunnelPacket, MessageError> {
        let header = TunnelMessageHeader::read(read)?;
        let message = TunnelMessage::read(read)?;

        Ok(Self { header, message })
    }

    /// Writes the tunnel packet to the provided serializer
    pub fn write(&self, write: &mut MessageSerializer) {
        self.header.write(write);
        self.message.write(write);
    }
}

/// Serializes the provided message into byte form, uses the provided
/// `tunnel_id` as the tunnel ID in the message header
pub fn serialize_message(tunnel_id: u32, message: &TunnelMessage) -> Vec<u8> {
    let mut write = MessageSerializer::default();
    let header = TunnelMessageHeader {
        version: VERSION,
        tunnel_id,
    };

    header.write(&mut write);
    message.write(&mut write);

    write.into_inner()
}

/// Deserializes a header and a message from the provided buffer
pub fn deserialize_message(buffer: &[u8]) -> Result<TunnelPacket, MessageError> {
    let mut read = MessageDeserializer::new(buffer);

    let header = TunnelMessageHeader::read(&mut read)?;
    let message = TunnelMessage::read(&mut read)?;

    Ok(TunnelPacket { header, message })
}

/// Writer for serializing various data types into a
/// byte buffer
#[derive(Default)]
pub struct MessageSerializer {
    /// Buffer bytes are serialized into
    buffer: Vec<u8>,
}

impl MessageSerializer {
    /// Writes a byte to the buffer
    #[inline]
    pub fn write_u8(&mut self, value: u8) {
        self.buffer.push(value)
    }

    /// Writes a collection of bytes to the buffer
    #[inline]
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.buffer.extend_from_slice(value)
    }

    /// Writes a 16bit unsigned int to the buffer
    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Writes a 32bit unsigned int to the buffer
    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Gets a slice of the underlying buffer
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Exchanges the serializer for the underlying buffer
    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }
}

/// Reader for deserializing various data types from a
/// byte buffer
pub struct MessageDeserializer<'a> {
    /// Buffer of bytes to read from
    buffer: &'a [u8],
    /// Current position within the buffer we have read up to
    cursor: usize,
}

impl<'a> MessageDeserializer<'a> {
    /// Creates a new deserializer from the buffer
    pub fn new(buffer: &'a [u8]) -> MessageDeserializer<'a> {
        MessageDeserializer { buffer, cursor: 0 }
    }

    /// Gets the total capacity of the underlying buffer
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Gets the length of the remaining unread buffer portion
    pub fn len(&self) -> usize {
        self.capacity() - self.cursor
    }

    /// Checks if the deserializer is empty
    pub fn is_empty(&self) -> bool {
        self.len() < 1
    }

    /// Reads a byte from the buffer
    pub fn read_u8(&mut self) -> Result<u8, MessageError> {
        if self.is_empty() {
            return Err(MessageError::Incomplete(1));
        }

        let value = self.buffer[self.cursor];
        self.cursor += 1;

        Ok(value)
    }

    /// Read a fixed constant time length slice of bytes from the buffer
    pub fn read_fixed<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], MessageError> {
        if self.len() < LENGTH {
            return Err(MessageError::Incomplete(LENGTH));
        }

        let mut buffer = [0u8; LENGTH];
        buffer.copy_from_slice(&self.buffer[self.cursor..self.cursor + LENGTH]);
        self.cursor += LENGTH;

        Ok(buffer)
    }

    /// Reads a 16bit unsigned integer from the buffer
    pub fn read_u16(&mut self) -> Result<u16, MessageError> {
        let value: [u8; 2] = self.read_fixed()?;
        let value = u16::from_be_bytes(value);
        Ok(value)
    }

    /// Reads a 32bit unsigned integer from the buffer
    pub fn read_u32(&mut self) -> Result<u32, MessageError> {
        let value: [u8; 4] = self.read_fixed()?;
        let value = u32::from_be_bytes(value);
        Ok(value)
    }

    /// Reads a runtime known length of bytes from the buffer
    pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], MessageError> {
        if self.len() < length {
            return Err(MessageError::Incomplete(self.len()));
        }

        let value = &self.buffer[self.cursor..self.cursor + length];
        self.cursor += length;
        Ok(value)
    }
}

/// Header before a tunnel message indicating the protocol version
/// and ID of the tunnel
#[derive(Debug)]
pub struct TunnelMessageHeader {
    /// Protocol version (For future sake)
    pub version: u8,
    /// ID of the tunnel this message is from, [u32::MAX] when the
    /// tunnel is not yet initiated
    pub tunnel_id: u32,
}

/// Errors that can occur while decoding
#[derive(Debug, Error)]
pub enum MessageError {
    /// Message type was unknown
    #[error("unknown message type")]
    UnknownMessageType,

    /// Message didn't have enough bytes to fully parse
    #[error("message wasn't long enough to read {0} bytes")]
    Incomplete(usize),
}

impl TunnelMessageHeader {
    /// Reads a tunnel message header from the provided deserializer
    pub fn read(buf: &mut MessageDeserializer<'_>) -> Result<TunnelMessageHeader, MessageError> {
        let version = buf.read_u8()?;
        let tunnel_id = buf.read_u32()?;

        Ok(Self { version, tunnel_id })
    }

    /// Writes the tunnel message header to the provided serializer
    pub fn write(&self, buf: &mut MessageSerializer) {
        buf.write_u8(self.version);
        buf.write_u32(self.tunnel_id);
    }
}

/// Different types of  messages that can be sent through the tunnel
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TunnelMessageType {
    /// Client is requesting to initiate a connection
    Initiate = 0x0,

    /// Server has accepted a connection
    Initiated = 0x1,

    /// Forward a message on behalf of the player to
    /// another player
    Forward = 0x2,

    /// Message to keep the stream alive
    /// (When the connect is inactive)
    KeepAlive = 0x3,
}

impl TryFrom<u8> for TunnelMessageType {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, MessageError> {
        Ok(match value {
            0x0 => Self::Initiate,
            0x1 => Self::Initiated,
            0x2 => Self::Forward,
            0x3 => Self::KeepAlive,
            _ => return Err(MessageError::UnknownMessageType),
        })
    }
}

/// Variants of the tunnel body
#[derive(Debug)]
pub enum TunnelMessage {
    /// Client is requesting to initiate a connection
    Initiate {
        /// Association token to authenticate with
        association_token: String,
    },

    /// Server created and associated the tunnel
    Initiated {
        /// Unique ID for the tunnel to include in future messages
        /// to identify itself
        tunnel_id: u32,
    },

    /// Client wants to forward a message
    Forward {
        /// Local socket pool index the message was sent to.
        /// Used to map to the target within the game
        index: u8,

        /// Message contents to forward
        message: Vec<u8>,
    },

    /// Keep alive
    KeepAlive,
}

impl TunnelMessage {
    /// Reads a tunnel message from the provided deserializer
    pub fn read(read: &mut MessageDeserializer<'_>) -> Result<TunnelMessage, MessageError> {
        // Read the message type byte
        let ty = read.read_u8()?;

        // Swap the constant message for the known type
        let ty = TunnelMessageType::try_from(ty)?;

        match ty {
            TunnelMessageType::Initiate => {
                // Determine token length
                let length = read.read_u16()? as usize;

                // Read token bytes and construct string
                let token_bytes = read.read_bytes(length)?;
                let token = String::from_utf8_lossy(token_bytes);

                Ok(TunnelMessage::Initiate {
                    association_token: token.to_string(),
                })
            }
            TunnelMessageType::Initiated => {
                let tunnel_id = read.read_u32()?;
                Ok(TunnelMessage::Initiated { tunnel_id })
            }
            TunnelMessageType::Forward => {
                let index = read.read_u8()?;

                // Get length of the association token
                let length = read.read_u16()? as usize;

                let message = read.read_bytes(length)?;

                Ok(TunnelMessage::Forward {
                    index,
                    message: message.to_vec(),
                })
            }
            TunnelMessageType::KeepAlive => Ok(TunnelMessage::KeepAlive),
        }
    }

    /// Writes the tunnel message to the provided serializer
    pub fn write(&self, write: &mut MessageSerializer) {
        match self {
            TunnelMessage::Initiate { association_token } => {
                debug_assert!(association_token.len() < u16::MAX as usize);
                write.write_u8(TunnelMessageType::Initiate as u8);

                write.write_u16(association_token.len() as u16);
                write.write_bytes(association_token.as_bytes());
            }
            TunnelMessage::Initiated { tunnel_id } => {
                write.write_u8(TunnelMessageType::Initiated as u8);
                write.write_u32(*tunnel_id);
            }
            TunnelMessage::Forward { index, message } => {
                write.write_u8(TunnelMessageType::Forward as u8);
                debug_assert!(message.len() < u16::MAX as usize);

                write.write_u8(*index);
                write.write_u16(message.len() as u16);
                write.write_bytes(message);
            }
            TunnelMessage::KeepAlive => {
                write.write_u8(TunnelMessageType::KeepAlive as u8);
            }
        }
    }
}
