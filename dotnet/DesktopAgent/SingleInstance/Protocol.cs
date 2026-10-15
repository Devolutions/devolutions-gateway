using System;
using System.IO;
using System.Text;

namespace Devolutions.Agent.Desktop.SingleInstance
{
    /// <summary>
    /// Wire format for forwarding command-line arguments to the running instance.
    /// </summary>
    /// <remarks>
    /// A message is a little-endian 32-bit payload length followed by the payload.
    /// The payload is a 32-bit argument count followed by each argument as a 32-bit byte length and its UTF-8 bytes.
    /// The server answers a valid message with a single <see cref="Ack"/> byte.
    /// </remarks>
    internal static class Protocol
    {
        public const int MaxPayloadSize = 32 * 1024;

        public const int MaxArgumentCount = 64;

        public const byte Ack = 0x06;

        private const int LengthSize = sizeof(int);

        private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        public static byte[] Encode(string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            if (args.Length > MaxArgumentCount)
            {
                throw new InvalidDataException("too many arguments");
            }

            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            // Reserve space for the payload length.
            writer.Write(0);
            writer.Write(args.Length);

            foreach (string arg in args)
            {
                byte[] bytes = Utf8.GetBytes(arg ?? string.Empty);
                writer.Write(bytes.Length);
                writer.Write(bytes);
            }

            writer.Flush();

            int payloadLength = (int)stream.Length - LengthSize;

            if (payloadLength > MaxPayloadSize)
            {
                throw new InvalidDataException("message too large");
            }

            byte[] message = stream.ToArray();
            WriteInt32(message, 0, payloadLength);

            return message;
        }

        public static string[] DecodePayload(byte[] payload)
        {
            if (payload is null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            int offset = 0;
            int count = ReadInt32(payload, ref offset);

            if (count < 0 || count > MaxArgumentCount)
            {
                throw new InvalidDataException("invalid argument count");
            }

            string[] args = new string[count];

            for (int i = 0; i < count; i++)
            {
                int length = ReadInt32(payload, ref offset);

                if (length < 0 || length > payload.Length - offset)
                {
                    throw new InvalidDataException("invalid argument length");
                }

                args[i] = Utf8.GetString(payload, offset, length);
                offset += length;
            }

            if (offset != payload.Length)
            {
                throw new InvalidDataException("unexpected trailing data");
            }

            return args;
        }

        public static void WriteMessage(Stream stream, string[] args)
        {
            byte[] message = Encode(args);
            stream.Write(message, 0, message.Length);
            stream.Flush();
        }

        public static string[] ReadMessage(Stream stream)
        {
            byte[] header = ReadExactly(stream, LengthSize);
            int offset = 0;
            int payloadLength = ReadInt32(header, ref offset);

            if (payloadLength < LengthSize || payloadLength > MaxPayloadSize)
            {
                throw new InvalidDataException("invalid message length");
            }

            return DecodePayload(ReadExactly(stream, payloadLength));
        }

        private static byte[] ReadExactly(Stream stream, int count)
        {
            byte[] buffer = new byte[count];
            int read = 0;

            while (read < count)
            {
                int n = stream.Read(buffer, read, count - read);

                if (n == 0)
                {
                    throw new EndOfStreamException("truncated message");
                }

                read += n;
            }

            return buffer;
        }

        private static int ReadInt32(byte[] buffer, ref int offset)
        {
            if (buffer.Length - offset < LengthSize)
            {
                throw new InvalidDataException("truncated message");
            }

            int value = buffer[offset] | buffer[offset + 1] << 8 | buffer[offset + 2] << 16 | buffer[offset + 3] << 24;
            offset += LengthSize;

            return value;
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }
    }
}
