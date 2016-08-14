using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;

namespace ZulassungsSharp
{
    public class BerTlvBlock
    {
        public enum TagClass : byte
        {
            Universal = 0x0,
            Application = 0x1,
            ContextSpecific = 0x2,
            Private = 0x3
        }

        public TagClass Class { get; protected set; }
        public bool Constructed { get; protected set; }
        public long TagNumber { get; protected set; }

        public string TagDescription =>
            $"{Class.ToString()[0]}{(Constructed ? "C" : "S")}{TagNumber}";

        public ImmutableArray<byte> RawBytes { get; protected set; }
        public ImmutableArray<BerTlvBlock> SubBlocks { get; protected set; }

        protected BerTlvBlock()
        {
        }

        public void Write(Stream stream)
        {
            WriteTag(stream);

            if (Constructed)
            {
                using (var buf = new MemoryStream())
                {
                    foreach (BerTlvBlock block in SubBlocks)
                    {
                        block.Write(buf);
                    }

                    buf.Seek(0, SeekOrigin.Begin);
                    WriteLength(stream, buf.Length);
                    buf.CopyTo(stream);
                }
            }
            else
            {
                WriteLength(stream, RawBytes.Length);
                var bytes = new byte[RawBytes.Length];
                RawBytes.CopyTo(bytes);
                stream.Write(bytes, 0, bytes.Length);
            }
        }

        protected void WriteTag(Stream stream)
        {
            // first byte: Cl Cl Co Tn Tn Tn Tn Tn
            var classByte = (byte)((byte)Class << 6);
            var constructedByte = (byte)(Constructed ? (1 << 5) : 0);

            if (TagNumber < 31)
            {
                // Cl Cl Co Tn Tn Tn Tn Tn
                var firstByte = (byte)(classByte | constructedByte | (byte)TagNumber);
                stream.WriteByte(firstByte);
            }
            else
            {
                // Cl Cl Co 1 1 1 1 1
                var firstByte = (byte)(classByte | constructedByte | 0x1F);
                stream.WriteByte(firstByte);

                Debug.Assert(TagNumber >= 0);

                // next bytes: 1 Tn Tn Tn Tn Tn Tn Tn
                // last byte: 0 Tn Tn Tn Tn Tn Tn Tn
                // shortest possible encoding

                long currentTagNumber = TagNumber;
                var tagBytes = new List<byte>();
                while (currentTagNumber > 0)
                {
                    tagBytes.Add((byte)(currentTagNumber & 0x7F));
                    currentTagNumber >>= 7;
                }

                // reverse for big endian
                tagBytes.Reverse();

                // set top bit on all tag bytes except the last
                for (int i = 0; i < tagBytes.Count - 1; ++i)
                {
                    tagBytes[i] |= (1 << 7);
                }
                stream.Write(tagBytes.ToArray(), 0, tagBytes.Count);
            }
        }

        protected void WriteLength(Stream stream, long length)
        {
            Debug.Assert(length >= 0);

            if (length < 0x80)
            {
                // short form!
                var lengthByte = (byte)length;
                stream.WriteByte(lengthByte);
                return;
            }

            // long form:
            // first byte: 1 C C C C C C C
            // subsequent bytes: L L L L L L L L
            // C is the number of subsequent bytes, must be less than 0b1111111

            var lengthBytes = new List<byte>();
            while (length > 0)
            {
                lengthBytes.Add((byte)(length & 0xFF));
                length >>= 8;
            }

            // reverse to get big endian
            lengthBytes.Reverse();

            Debug.Assert(lengthBytes.Count < 0x7F);

            var countByte = (byte) ((1 << 7) | lengthBytes.Count);
            stream.WriteByte(countByte);
            stream.Write(lengthBytes.ToArray(), 0, lengthBytes.Count);
        }

        public static BerTlvBlock CreateFromStream(Stream stream)
        {
            int firstByteInt = stream.ReadByte();
            if (firstByteInt == -1)
            {
                // end of stream, nothing to create
                return null;
            }
            byte firstByte = (byte) firstByteInt;

            var block = new BerTlvBlock
            {
                Class = (TagClass)((firstByte >> 6) & 0x3),
                Constructed = ((firstByte & (1 << 5)) != 0)
            };
            long tagNumber = (firstByte & 0x1F);
            if (tagNumber == 0x1F)
            {
                // long form tag number...
                tagNumber = 0;
                for (;;)
                {
                    byte tagByte = ReadByteOrThrow(stream);
                    tagNumber = checked(tagNumber << 7);
                    tagNumber |= (byte)(tagByte & 0x7F);

                    // top bit 1 = more bytes follow
                    if ((tagByte & 0x80) == 0)
                    {
                        // enough
                        break;
                    }
                }
            }
            block.TagNumber = tagNumber;

            long length = ReadByteOrThrow(stream);
            if (length == 0x80)
            {
                throw new NotImplementedException("indefinite lengths are not supported");
            }
            else if (length > 0x80)
            {
                // multi-byte length
                int lengthBytes = (int)(length & 0x7F);
                length = 0;
                for (int i = 0; i < lengthBytes; ++i)
                {
                    length = checked(length << 8);
                    length |= ReadByteOrThrow(stream);
                }
            }
            
            var bytes = new byte[checked((int)length)];
            ReadOrThrow(stream, bytes, 0, bytes.Length);

            if (block.Constructed)
            {
                var builder = ImmutableArray.CreateBuilder<BerTlvBlock>();
                using (var subStream = new MemoryStream(bytes, writable: false))
                {
                    BerTlvBlock subBlock;
                    for (;;)
                    {
                        subBlock = CreateFromStream(subStream);
                        if (subBlock == null)
                        {
                            break;
                        }
                        builder.Add(subBlock);
                    }
                }
                block.SubBlocks = builder.ToImmutable();
            }
            else
            {
                block.RawBytes = ImmutableArray.Create(bytes);
            }

            return block;
        }

        protected static byte ReadByteOrThrow(Stream stream)
        {
            int b = stream.ReadByte();
            if (b == -1)
            {
                throw new EndOfStreamException();
            }
            return (byte) b;
        }

        protected static void ReadOrThrow(Stream stream, byte[] buf, int offset, int count)
        {
            while (count > 0)
            {
                int bytesRead = stream.Read(buf, offset, count);
                if (bytesRead == 0)
                {
                    throw new EndOfStreamException();
                }
                offset += bytesRead;
                count -= bytesRead;
            }
        }

        [ContractInvariantMethod]
        private void ClassInvariant()
        {
            Contract.Invariant(Enum.IsDefined(typeof(TagClass), Class));
            Contract.Invariant(TagNumber >= 0);
            Contract.Invariant(Constructed || SubBlocks.IsEmpty);
            Contract.Invariant(!Constructed || RawBytes.IsEmpty);
        }
    }
}
