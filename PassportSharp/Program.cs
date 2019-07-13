using System;
using System.IO;
using System.Linq;
using System.Text;
using CommandLine;
using PCSC;
using PCSC.Iso7816;
using SmartCardGrabBag;

namespace PassportSharp
{
    class Program
    {
        class Options
        {
            [Option('l', "list-readers", SetName = "list-readers", Default = false, HelpText = "List readers instead of reading a passport.")]
            public bool ListReaders { get; set; }

            [Option('r', "reader", SetName = "run", Default = 0, MetaValue = "INDEX", HelpText = "The index of the card reader to use.")]
            public int ReaderIndex { get; set; }

            [Option('m', "mrz-file", SetName = "run", Required = true, MetaValue = "FILENAME", HelpText = "The filename of the file containing the travel document's MRZ data.")]
            public string MRZFileName { get; set; }
        }

        static int Main(string[] args)
        {
            var factory = new ContextFactory();
            using (var ctx = factory.Establish(SCardScope.System))
            {
                Options opts = null;
                Parser.Default.ParseArguments<Options>(args)
                    .WithParsed(o => { opts = o; });

                if (opts == null)
                {
                    return 1;
                }

                if (opts.ListReaders)
                {
                    ListReaders(ctx);
                    return 0;
                }

                string readerName = ctx.GetReaders()[opts.ReaderIndex];
                return ReadPassport(ctx, readerName, opts.MRZFileName);
            }
        }

        static int ReadPassport(ISCardContext ctx, string readerName, string mrzFileName)
        {
            string mrzText = LoadMRZ(mrzFileName);

            using (var lowReader = new SCardReader(ctx))
            using (var reader = new IsoReader(lowReader, disconnectReaderOnDispose: false))
            {
                reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.T1);

                try
                {
                    if (CardSupportsPACE(reader))
                    {
                        Console.Error.WriteLine("card supports PACE; no PACE support implemented");
                        return 1;
                    }

                    // basic auth

                    // switch to MRTD app (this must happen before EXTERNAL AUTHENTICATE!)
                    {
                        var selAppCmd = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
                        {
                            CLA = 0x00,
                            Instruction = InstructionCode.SelectFile,
                            P1 = 0x04,  // directly by DF (data file) name
                            P2 = 0x0C,  // first record, no response
                            Data = new byte[]
                            {
                                0xA0, 0x00, 0x00, 0x02,
                                0x47, 0x10, 0x01,
                            }
                        };
                        Response selAppResp = reader.Transmit(selAppCmd);
                        if (selAppResp.StatusWord != 0x9000)
                        {
                            throw new PassportCommunicationException(
                                "selecting eMRTD application",
                                selAppResp.StatusWord
                            );
                        }
                    }

                    var mrz = MachineReadableZone.Parse(mrzText);
                    IIsoReader secureReader = BasicAccessControl.Authenticate(mrz, reader);

                    // try selecting EF.COM (general info about the chip data)
                    if (false)
                    {
                        var selCmd = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
                        {
                            CLA = 0x00,
                            Instruction = InstructionCode.SelectFile,
                            P1 = 0x02,  // EF under current DF
                            P2 = 0x0C,  // first occurrence, no data
                            Data = new byte[] {
                                0x01, 0x1E
                            }
                        };
                        Response selResp = secureReader.Transmit(selCmd);
                        if (selResp.StatusWord != 0x9000)
                        {
                            throw new PassportCommunicationException(
                                "selecting EF.COM",
                                selResp.StatusWord
                            );
                        }
                    }

                    // try selecting a file
                    {
                        var selCmd = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
                        {
                            CLA = 0x00,
                            Instruction = InstructionCode.SelectFile,
                            P1 = 0x02,  // EF under current DF
                            P2 = 0x0C,  // first occurrence, no data
                            Data = new byte[] {
                                0x01, 0x02
                            }
                        };
                        Response selResp = secureReader.Transmit(selCmd);
                        if (selResp.StatusWord != 0x9000)
                        {
                            throw new PassportCommunicationException(
                                "selecting file",
                                selResp.StatusWord
                            );
                        }
                    }

                    // try reading it
                    BerTlvBlock picture;
                    using (var strm = new MemoryStream())
                    {
                        ushort offset = 0;
                        for (;;)
                        {
                            var readCmd = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
                            {
                                CLA = 0x00,
                                Instruction = InstructionCode.ReadBinary,
                                P1 = (byte)((offset >> 8) & 0xFF),
                                P2 = (byte)((offset >> 0) & 0xFF),
                                Le = 0x00,
                            };
                            Response readResp = secureReader.Transmit(readCmd);
                            if (readResp.StatusWord == 0x6B00)
                            {
                                // I think we're done
                                break;
                            }
                            else if (readResp.StatusWord != 0x9000)
                            {
                                throw new PassportCommunicationException(
                                    "reading file",
                                    readResp.StatusWord
                                );
                            }
                            byte[] readData = readResp.GetData();
                            strm.Write(readData, 0, readData.Length);
                            offset = (ushort)(offset + readData.Length);
                        }

                        strm.Position = 0;
                        picture = BerTlvBlock.CreateFromStream(strm);
                        Hexy.PrintBerTlvBlockDump(picture, bytesPerLine: 16);
                    }
                }
                finally
                {
                    reader.Disconnect(SCardReaderDisposition.Reset);
                }
            }

            return 0;
        }

        static void ListReaders(ISCardContext ctx)
        {
            foreach (var (index, reader) in ctx.GetReaders().Select((r, i) => (i, r)))
            {
                Console.WriteLine($"{index}: {reader}");
            }
        }

        static string LoadMRZ(string mrzFileName)
        {
            // normalizes newlines and removes blank lines
            return string.Join(
                "\n",
                File.ReadAllText(mrzFileName, Encoding.UTF8)
                    .Replace("\r", "\n")
                    .Split("\n")
                    .Select(ln => ln.Trim())
                    .Where(ln => ln.Length > 0)
            );
        }

        static bool CardSupportsPACE(IIsoReader reader)
        {
            // check if PACE is supported
            {
                // select EF.CardAccess
                var selCmd = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
                {
                    CLA = 0x00,
                    Instruction = InstructionCode.SelectFile,
                    P1 = 0x00, // select MF/DF/EF
                    P2 = 0x0C, // first occurrence, no response
                    Data = new byte[] {
                        0x3F, 0x1C, // EF.CardAccess
                    },
                };
                Response selResp = reader.Transmit(selCmd);
                if (selResp.StatusWord == 0x9000)
                {
                    // yup
                    return true;
                }
                else if (selResp.StatusWord == 0x6A82)
                {
                    // file not found
                    return false;
                }
                else
                {
                    throw new PassportCommunicationException(
                        "selecting EF.CardAccess when checking for PACE support",
                        selResp.StatusWord
                    );
                }
            }
        }
    }
}
