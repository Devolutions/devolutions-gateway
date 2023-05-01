# JMUX Specification

JMUX is a wire protocol for multiplexing connections or streams into a single connection. It is inspired by the [SSH Connection Protocol](https://tools.ietf.org/html/rfc4254#page-5) and [QMUX](https://github.com/progrium/qmux).

## Common Definitions

   All JMUX messages share a common 4-byte header structure:

      uint8     msgType
      uint8     msgFlags
      uint16    msgSize

   The **msgType** field contains one of the following values:

      JMUX_MSG_CHANNEL_OPEN                    100
      JMUX_MSG_CHANNEL_OPEN_SUCCESS            101
      JMUX_MSG_CHANNEL_OPEN_FAILURE            102
      JMUX_MSG_CHANNEL_WINDOW_ADJUST           103
      JMUX_MSG_CHANNEL_DATA                    104
      JMUX_MSG_CHANNEL_EOF                     105
      JMUX_MSG_CHANNEL_CLOSE                   106
   
   The **msgFlags** field is reserved. All reserved fields MUST be set to zero and their values ignored.

   The **msgSize** field is the size of the complete message including the header.

   All integer fields are in network byte order (big endian).

   All string fields are UTF-8 strings without a null terminator.

## Channels

   Either side may open a channel. Multiple channels are multiplexed into a single connection.

   Channels are identified by numbers at each end. The number referring to a channel may be different on each side. Requests to open a channel contain the sender's channel number. Any other channel-related messages contain the recipient's channel number for the channel.

   Channels are flow-controlled. No data may be sent to a channel until a message is received to indicate that window space is available.

###  Opening a Channel

   When either side wishes to open a new channel, it allocates a local number for the channel. It then sends the following message to the other side, and includes the local channel number and initial window size in the message.

      uint8     msgType (JMUX_MSG_CHANNEL_OPEN)
      uint8     msgFlags
      uint16    msgSize
      uint32    senderChannelId
      uint32    initialWindowSize
      uint32    maximumPacketSize
      uint8[*]  destinationUrl

   **senderChannelId** is a local identifier for the channel used by the sender of this message. **initialWindowSize** specifies how many bytes of channel data can be sent to the sender of this message without adjusting the window. The **maximumPacketSize** specifies the maximum size of an individual data packet that can be sent to the sender. **destinationUrl** is a string containing the destination URL for the channel:

   * tcp://google.com:443
   * tcp://192.168.1.100:3389

   The URL string SHOULD NOT be null-terminated, but implementations SHOULD ignore null terminators if they are present.

   The remote side then decides whether it can open the channel, and responds with either `JMUX_MSG_CHANNEL_OPEN_SUCCESS` or `JMUX_MSG_CHANNEL_OPEN_FAILURE`.

      uint8     msgType (JMUX_MSG_CHANNEL_OPEN_SUCCESS)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId
      uint32    senderChannelId
      uint32    initialWindowSize
      uint32    maximumPacketSize

   The **recipientChannelId** is the channel number given in the original open request, and **senderChannelId** is the channel number allocated by the other side.

      uint8     msgType (JMUX_MSG_CHANNEL_OPEN_FAILURE)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId
      uint32    reasonCode
      uint8[*]  description

   The **reasonCode** is used to indicate the reason for the channel opening failure. The **description** field is optional and contains a textual explanation for the failure if it is present.

###  Data Transfer

   The window size specifies how many bytes the other party can send before it must wait for the window to be adjusted. Both parties use the following message to adjust the window.

      uint8     msgType (JMUX_MSG_CHANNEL_WINDOW_ADJUST)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId
      uint32    windowAdjustment

   After receiving this message, the recipient MAY send the given number of bytes more than it was previously allowed to send; the window size is incremented. Implementations MUST correctly handle window sizes of up to 2^32 - 1 bytes. The window MUST NOT be increased above 2^32 - 1 bytes.

   Data transfer is done with messages of the following type.

      uint8     msgType (JMUX_MSG_CHANNEL_DATA)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId
      uint8[*]  transferData

   The maximum amount of data allowed is determined by the maximum packet size for the channel, and the current window size, whichever is smaller. The window size is decremented by the amount of data sent. Both parties MAY ignore all extra data sent after the allowed window is empty.

   Implementations are expected to have some limit on the transport layer packet size.

###  Closing a Channel

   When a party will no longer send more data to a channel, it SHOULD send `JMUX_MSG_CHANNEL_EOF`.

      uint8     msgType (JMUX_MSG_CHANNEL_EOF)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId

   No explicit response is sent to this message. However, the application may send EOF to whatever is at the other end of the channel. Note that the channel remains open after this message, and more data may still be sent in the other direction. This message does not consume window space and can be sent even if no window space is available.

   When either party wishes to terminate the channel, it sends `JMUX_MSG_CHANNEL_CLOSE`. Upon receiving this message, a party MUST send back an `JMUX_MSG_CHANNEL_CLOSE` unless it has already sent this message for the channel. The channel is considered closed for a party when it has both sent and received `JMUX_MSG_CHANNEL_CLOSE`, and the party may then reuse the channel number. A party MAY send `JMUX_MSG_CHANNEL_CLOSE` without having sent or received `JMUX_MSG_CHANNEL_EOF`.

      uint8     msgType (JMUX_MSG_CHANNEL_CLOSE)
      uint8     msgFlags
      uint16    msgSize
      uint32    recipientChannelId

   This message does not consume window space and can be sent even if no window space is available.

   It is RECOMMENDED that all data sent before this message be delivered to the actual destination, if possible.
