using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using PCSC;
using PCSC.Iso7816;

namespace ZulassungsSharp
{
    class Program
    {
        static byte[] ObtainData(IsoReader reader, ushort dataID)
        {
            var selectApdu = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
            {
                CLA = 0x00,
                Instruction = InstructionCode.SelectFile,
                P1 = 0x02,  // specific elementary file under current data file
                P2 = 0x0C,  // first record, ?? template
                Data = new[]
                {
                    (byte)((dataID >> 8) & 0xFF),
                    (byte)((dataID >> 0) & 0xFF)
                }
            };
            var selectResponse = reader.Transmit(selectApdu);
            if (selectResponse.StatusWord != 0x9000)
            {
                Console.Error.WriteLine("E002!");
                return null;
            }

            var readApdu = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
            {
                CLA = 0x00,
                Instruction = InstructionCode.ReadBinary,
                P1 = 0x00,
                P2 = 0x00,
                Le = 0x00
            };

            var buffer = new List<byte>();
            for (byte offset = 0; offset < 16; ++offset)
            {
                readApdu.P1 = offset;
                var readResponse = reader.Transmit(readApdu);
                if (readResponse.StatusWord == 0x6B00)
                {
                    // enough
                    break;
                }

                buffer.AddRange(readResponse.GetData());
            }
            return buffer.ToArray();
        }

        static void ReadFromSmartCard()
        {
            CommandApdu apdu;
            Response response;
            byte[] responseData;

            var factory = new ContextFactory();
            using (var ctx = factory.Establish(SCardScope.System))
            {
                string readerName = ctx.GetReaders().First();
                using (var reader = new IsoReader(ctx, readerName, SCardShareMode.Exclusive, SCardProtocol.T1, releaseContextOnDispose: false))
                {
                    apdu = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
                    {
                        CLA = 0x00,
                        Instruction = InstructionCode.SelectFile,
                        P1 = 0x04,  // directly by DF (data file) name
                        P2 = 0x0C,  // first record, ?? template
                        Data = new byte[]
                        {
                            0xA0, 0x00, 0x00, 0x04,
                            // "VEVR-01"
                            0x56, 0x45, 0x56, 0x52, 0x2D, 0x30, 0x31
                        }
                    };
                    response = reader.Transmit(apdu);
                    if (response.StatusWord != 0x9000)
                    {
                        Console.Error.WriteLine("E013a!");
                        return;
                    }

                    apdu = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
                    {
                        CLA = 0xA0,
                        Instruction = InstructionCode.GetData,
                        P1 = 0x9F,  // 2-byte BER-TLV tag
                        P2 = 0x6A,  // 2-byte BER-TLV tag
                        Le = 0x00
                    };
                    response = reader.Transmit(apdu);
                    responseData = response.GetData();
                    if (responseData[0] != 0x47 || responseData[1] != 0x44)
                    {
                        Console.Error.WriteLine("E013b!");
                        return;
                    }

                    var sections = new ushort[]
                    {
                        0xD001, 0xE001, 0xC001,
                        0xD011, 0xE011, 0xC011,
                        0xD021, 0xE021, 0xC021
                    };
                    foreach (ushort section in sections)
                    {
                        using (var o = new FileStream($"{section:X4}.bin", FileMode.Create, FileAccess.Write,
                            FileShare.None))
                        {
                            byte[] data = ObtainData(reader, section);
                            o.Write(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            ReadFromSmartCard();

            var sections = new ushort[] {0x001, 0x011, 0x021};
            foreach (ushort section in sections)
            {
                ushort certificateSection = (ushort)(section | 0xC000);
                ushort dataSection = (ushort) (section | 0xD000);
                ushort signatureSection = (ushort) (section | 0xE000);

                byte[] certificateBytes = File.ReadAllBytes($"{certificateSection:X4}.bin");
                byte[] dataBytes = File.ReadAllBytes($"{dataSection:X4}.bin");
                byte[] signatureBytes = File.ReadAllBytes($"{signatureSection:X4}.bin");

                BerTlvBlock signatureObject;
                using (var signatureStream = new MemoryStream(signatureBytes, writable: false))
                {
                    signatureObject = BerTlvBlock.CreateFromStream(signatureStream);
                }

                // ECDSA signature (as integer pair r, s) of SHA256 digest of data
                var hasher = new Sha256Digest();
                var hashBytes = new byte[hasher.GetDigestSize()];
                hasher.BlockUpdate(dataBytes, 0, dataBytes.Length);
                hasher.DoFinal(hashBytes, 0);

                byte[] rBytes = signatureObject.SubBlocks[0].RawBytes.ToArray();
                byte[] sBytes = signatureObject.SubBlocks[1].RawBytes.ToArray();
                var r = new BigInteger(rBytes);
                var s = new BigInteger(sBytes);

                var cert = X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certificateBytes));
                var pubkey = (ECPublicKeyParameters) PublicKeyFactory.CreateKey(cert.SubjectPublicKeyInfo);

                var signer = new ECDsaSigner();
                signer.Init(forSigning: false, parameters: pubkey);
                if (signer.VerifySignature(hashBytes, r, s))
                {
                    Console.WriteLine("signature OK");
                }
                else
                {
                    Console.WriteLine("SIGNATURE BAD!!!");
                }

                var dataBlocks = new List<BerTlvBlock>();
                using (var dataStream = new MemoryStream(dataBytes, writable: false))
                {
                    for (;;)
                    {
                        var block = BerTlvBlock.CreateFromStream(dataStream);
                        if (block == null)
                        {
                            break;
                        }
                        dataBlocks.Add(block);
                    }
                }

                foreach (var dataBlock in dataBlocks)
                {
                    OutputBlock(dataBlock);
                }
            }
        }

        static void OutputBlock(BerTlvBlock block, int depth = 0)
        {
            var indent = new string(' ', 2*depth);
            if (block.Constructed)
            {
                Console.WriteLine($"{indent}{block.TagNumber}:");
                foreach (var subBlock in block.SubBlocks)
                {
                    OutputBlock(subBlock, depth + 1);
                }
            }
            else
            {
                var bytes = block.RawBytes.ToArray();
                var encoding = Encoding.GetEncoding("windows-1252");
                var text = encoding.GetString(bytes);
                Console.WriteLine($"{indent}{block.TagNumber}: {text}");
            }
        }
    }
}
