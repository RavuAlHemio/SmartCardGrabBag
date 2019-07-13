using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using PCSC;
using PCSC.Iso7816;
using SmartCardGrabBag;

namespace PassportSharp
{
    public class ThreeDesSecuredReader : IIsoReader
    {
        public IIsoReader UnderlyingReader { get; protected set; }
        protected KeyParameter SessionEncryptionKey { get; set; }
        protected IMac Authenticator { get; set; }
        protected byte[] SendSequenceCounter { get; set; }

        public ThreeDesSecuredReader(IIsoReader underlyingReader, byte[] sessEncKey, byte[] sessMacKey, byte[] seqCounter)
        {
            Contract.Requires(sessEncKey.Length == 16);
            Contract.Requires(sessMacKey.Length == 16);
            Contract.Requires(seqCounter.Length == 8);

            UnderlyingReader = underlyingReader;
            SessionEncryptionKey = new KeyParameter(sessEncKey.ToArray());

            Authenticator = new ISO9797Alg3Mac(
                new DesEngine(),
                8*8, // 8 byte MAC length
                null // no padding
            );
            Authenticator.Init(new KeyParameter(sessMacKey));

            SendSequenceCounter = seqCounter.ToArray();
        }

        public string ReaderName => UnderlyingReader.ReaderName;
        public SCardProtocol ActiveProtocol => UnderlyingReader.ActiveProtocol;
        public SCardShareMode CurrentShareMode => UnderlyingReader.CurrentShareMode;
        public int RetransmitWaitTime { get => UnderlyingReader.RetransmitWaitTime; set => UnderlyingReader.RetransmitWaitTime = value; }
        public int MaxReceiveSize => UnderlyingReader.MaxReceiveSize;
        public void Connect(string readerName, SCardShareMode mode, SCardProtocol protocol) => UnderlyingReader.Connect(readerName, mode, protocol);
        public CommandApdu ConstructCommandApdu(IsoCase isoCase) => UnderlyingReader.ConstructCommandApdu(isoCase);
        public void Disconnect(SCardReaderDisposition disposition) => UnderlyingReader.Disconnect(disposition);

        protected byte[] Crypt(byte[] what, bool encrypt = true)
        {
            var encryptor = new CbcBlockCipher(new DesEdeEngine());
            encryptor.Init(forEncryption: encrypt, parameters: new ParametersWithIV(
                SessionEncryptionKey,
                new byte[8]
            ));
            return encryptor.ProcessMultipleBlocks(what);
        }

        public Response Transmit(CommandApdu commandApdu)
        {
            if (commandApdu.CLA != 0x00)
            {
                throw new ArgumentException($"{nameof(commandApdu.CLA)} must be 0x00 (is 0x{commandApdu.CLA:X2})");
            }

            var fullBody = new List<byte>();

            if (commandApdu.Case.IsSendingData())
            {
                bool use0x85 = false;

                // pad data
                var newData = new List<byte>(commandApdu.Data);
                AddICAOPadding(newData);

                // encrypt
                var prefixedEncryptedData = new List<byte>();
                if (!use0x85)
                {
                    prefixedEncryptedData.Add(0x01); // prefix, for some reason
                }
                prefixedEncryptedData.AddRange(Crypt(newData.ToArray(), encrypt: true));

                // pack into BER-TLV 0x87 (or 0x85)
                // 0b1000_0111 = 0x87
                //   10.._.... = class == context-specific
                //   ..0._.... = not constructed
                //   ...0_0111 = tag number = 0x07
                var dataBerTlv = new BerTlvBlock(
                    BerTlvBlock.TagClass.ContextSpecific,
                    use0x85 ? 0x05 : 0x07,
                    prefixedEncryptedData.ToArray()
                );

                // and append
                fullBody.AddRange(dataBerTlv.ToArray());
            }

            if (commandApdu.Case.IsReceivingData())
            {
                // pack expected count into BER-TLV 0x97
                // 0b1001_0111 = 0x97
                //   10.._.... = class == context-specific
                //   ..0._.... = not constructed
                //   ...1_0111 = tag number = 0x17
                byte[] lengthBytes;
                switch (commandApdu.Case)
                {
                    case IsoCase.Case2Short:
                    case IsoCase.Case4Short:
                        lengthBytes = new byte[] { (byte)commandApdu.Le };
                        break;
                    case IsoCase.Case2Extended:
                    case IsoCase.Case4Extended:
                        lengthBytes = new byte[] {
                            unchecked((byte)((commandApdu.Le >> 8) & 0xFF)),
                            unchecked((byte)((commandApdu.Le >> 0) & 0xFF)),
                        };
                        break;
                    default:
                        throw new PassportCryptoException(
                            "packing expected response length",
                            "unexpected command APDU ISO case"
                        );
                }

                var expectedBerTlv = new BerTlvBlock(
                    BerTlvBlock.TagClass.ContextSpecific,
                    0x17,
                    lengthBytes
                );

                // and append
                fullBody.AddRange(expectedBerTlv.ToArray());
            }

            // calculate updated, padded header for MAC calculation
            var macHeader = new byte[] {
                0x0C, // CLA -- different class for secure communication
                commandApdu.INS,
                commandApdu.P1,
                commandApdu.P2,
                0x80, // initial padding byte
                0x00, // trailing padding bytes to multiple of 8...
                0x00,
                0x00
            };

            // increment SSC; concat SSC, macHeader and body; and calculate MAC of the result
            SendSequenceCounter.Increment();
            var messageToMac = new List<byte>();
            messageToMac.AddRange(SendSequenceCounter);
            messageToMac.AddRange(macHeader);
            messageToMac.AddRange(fullBody);
            AddICAOPadding(messageToMac);
            byte[] mac = Authenticator.Calculate(messageToMac.ToArray());

            // slap MAC into BER-TLV 0x8E and append to body
            // 0b1000_1110 = 0x8E
            //   10.._.... = class == context-specific
            //   ..0._.... = not constructed
            //   ...0_1110 = tag number = 0x0E
            var macBerTlv = new BerTlvBlock(
                BerTlvBlock.TagClass.ContextSpecific,
                0x0E,
                mac
            );
            fullBody.AddRange(macBerTlv.ToArray());

            // finally, construct actual APDU
            var secureCmd = new CommandApdu(IsoCase.Case4Short, commandApdu.Protocol)
            {
                CLA = 0x0C, // CLA -- different class for secure communication
                INS = commandApdu.INS,
                P1 = commandApdu.P1,
                P2 = commandApdu.P2,
                Data = fullBody.ToArray(),
                Le = 0x00, // any length
            };

            // send the APDU
            Response secureResp = UnderlyingReader.Transmit(secureCmd);

            // obtain the response contents
            byte[] respAll = secureResp.GetData();
            if (respAll == null)
            {
                // no response data; return the response raw
                return secureResp;
            }

            // deblockify
            var respBlocks = new List<BerTlvBlock>();
            using (var respStream = new MemoryStream(respAll, writable: false))
            {
                for (;;)
                {
                    var respBlock = BerTlvBlock.CreateFromStream(respStream);
                    if (respBlock == null)
                    {
                        break;
                    }
                    respBlocks.Add(respBlock);
                }
            }

            // increment sequence counter and calculate MAC (MAC block is 0x8E)
            SendSequenceCounter.Increment();
            var respMacBytes = new List<byte>();
            respMacBytes.AddRange(SendSequenceCounter);
            IEnumerable<BerTlvBlock> respNonMacBlocks = respBlocks.Where(blk =>
                blk.TagNumber != 0x0E
                || blk.Class != BerTlvBlock.TagClass.ContextSpecific
                || blk.Constructed
            );
            foreach (BerTlvBlock blk in respNonMacBlocks)
            {
                respMacBytes.AddRange(blk.ToArray());
            }
            AddICAOPadding(respMacBytes);

            byte[] calcMac = Authenticator.Calculate(respMacBytes.ToArray());
            // obtain MAC
            BerTlvBlock macBlock = respBlocks.FirstOrDefault(blk =>
                blk.TagNumber == 0x0E
                && blk.Class == BerTlvBlock.TagClass.ContextSpecific
                && !blk.Constructed
            );
            if (macBlock != null)
            {
                if (!calcMac.SequenceEqual(macBlock.RawBytes))
                {
                    throw new PassportCryptoException(
                        "verifying secure response",
                        "MAC verification failed"
                    );
                }
            }

            // obtain status block (0x99)
            BerTlvBlock statusBlock = respBlocks.FirstOrDefault(blk =>
                blk.TagNumber == 0x19
                && blk.Class == BerTlvBlock.TagClass.ContextSpecific
                && !blk.Constructed
            );
            byte statusLeading, statusTrailing;
            if (statusBlock != null)
            {
                statusLeading = statusBlock.RawBytes[0];
                statusTrailing = statusBlock.RawBytes[1];
            }
            else
            {
                statusLeading = secureResp.SW1;
                statusTrailing = secureResp.SW2;
            }

            // obtain data block, if any (0x87)
            BerTlvBlock dataBlock = respBlocks.FirstOrDefault(blk =>
                blk.TagNumber == 0x07
                && blk.Class == BerTlvBlock.TagClass.ContextSpecific
                && !blk.Constructed
            );
            byte[] decryptedData = null;
            if (dataBlock != null)
            {
                if (dataBlock.RawBytes[0] != 0x01)
                {
                    throw new PassportCryptoException(
                        "decrypting secure response",
                        "first byte of cipher block is not 0x01"
                    );
                }

                byte[] dataToDecrypt = dataBlock.RawBytes
                    .Skip(1)
                    .ToArray();
                byte[] decryptedPaddedData = Crypt(dataToDecrypt, encrypt: false);

                int? paddingStartIndex = null;
                for (int i = decryptedPaddedData.Length - 1; i >= 0; --i)
                {
                    if (decryptedPaddedData[i] == 0x80)
                    {
                        // padding terminator
                        paddingStartIndex = i;
                        break;
                    }
                    else if (decryptedPaddedData[i] != 0x00)
                    {
                        // not a padding byte
                        throw new PassportCryptoException(
                            "decrypting secure response",
                            "decrypted data does not correctly end in padding"
                        );
                    }
                }

                if (paddingStartIndex.HasValue)
                {
                    decryptedData = new byte[paddingStartIndex.Value];
                    Array.Copy(decryptedPaddedData, 0, decryptedData, 0, paddingStartIndex.Value);
                }
                else
                {
                    decryptedData = decryptedPaddedData;
                }
            }

            var responseApduBytes = new List<byte>();
            if (decryptedData != null)
            {
                responseApduBytes.AddRange(decryptedData);
            }
            responseApduBytes.Add(statusLeading);
            responseApduBytes.Add(statusTrailing);
            var responseApdu = new ResponseApdu(
                responseApduBytes.ToArray(),
                commandApdu.Case,
                commandApdu.Protocol
            );

            var decryptedResponse = new Response(
                Enumerable.Repeat(responseApdu, 1),
                Enumerable.Empty<SCardPCI>()
            );
            return decryptedResponse;
        }

        static void AddICAOPadding(IList<byte> bytes, int toMultipleOf = 8)
        {
            bytes.Add(0x80);
            while (bytes.Count % toMultipleOf != 0)
            {
                bytes.Add(0x00);
            }
        }

        #region dispose pattern
        private bool _disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                // free managed objects
                UnderlyingReader.Dispose();
            }

            // free unmanaged objects
            // (uncomment finalizer if any!)

            _disposed = true;
        }

        /*
        ~ThreeDesSecuredReader()
        {
            Dispose(false);
        }
        */
        #endregion
    }
}
