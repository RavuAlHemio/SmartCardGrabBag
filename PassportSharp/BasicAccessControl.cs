using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using PCSC.Iso7816;
using SmartCardGrabBag;

namespace PassportSharp
{
    public static class BasicAccessControl
    {
        internal static (byte[] EncryptionKey, byte[] MACKey) DeriveKeysFromMRZ(MachineReadableZone mrz)
        {
            var mrzInfo = new StringBuilder();
            mrzInfo.Append(mrz.DocumentNumber);
            if (mrzInfo.Length < 9)
            {
                mrzInfo.Append(MachineReadableZone.FillerCharacter, 9 - mrzInfo.Length);
            }
            mrzInfo.Append(MachineReadableZone.CalculateCheckDigit(mrz.DocumentNumber));
            mrzInfo.Append(mrz.DateOfBirth);
            mrzInfo.Append(MachineReadableZone.CalculateCheckDigit(mrz.DateOfBirth));
            mrzInfo.Append(mrz.DateOfExpiry);
            mrzInfo.Append(MachineReadableZone.CalculateCheckDigit(mrz.DateOfExpiry));

            var sha1 = new Sha1Digest();
            byte[] mrzSha1 = sha1.Calculate(Encoding.UTF8.GetBytes(mrzInfo.ToString()));
            byte[] mrzSeed = mrzSha1.Take(16).ToArray();

            byte[] encKey = Derive3DESKey(mrzSeed, 1);
            byte[] macKey = Derive3DESKey(mrzSeed, 2);
            return (encKey, macKey);
        }

        internal static byte[] Derive3DESKey(byte[] seed, int c)
        {
            if (seed.Length != 16)
            {
                throw new ArgumentException($"{nameof(seed)} must have length 16 (has {seed.Length})", nameof(seed));
            }

            // d = seed ++ c
            var d = new byte[20];
            Array.Copy(seed, 0, d, 0, 16);
            d[16] = (byte)(((uint)c >> 24) & 0xFF);
            d[17] = (byte)(((uint)c >> 16) & 0xFF);
            d[18] = (byte)(((uint)c >>  8) & 0xFF);
            d[19] = (byte)(((uint)c >>  0) & 0xFF);

            var sha1 = new Sha1Digest();
            byte[] hSha1 = sha1.Calculate(d);
            return hSha1.Take(16).ToArray(); // for mode K1, K2, K1
        }

        internal static byte[] RequestNonce(IIsoReader reader)
        {
            // get challenge
            var getChlgCmd = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
            {
                CLA = 0x00,
                Instruction = InstructionCode.GetChallenge,
                P1 = 0x00, // no algorithm
                P2 = 0x00, // reserved
                Le = 0x08, // eight-byte nonce
            };
            Response getChlgResp = reader.Transmit(getChlgCmd);
            if (getChlgResp.StatusWord != 0x9000)
            {
                throw new PassportCommunicationException(
                    "obtaining nonce for basic access control",
                    getChlgResp.StatusWord
                );
            }
            return getChlgResp.GetData();
        }

        internal static byte[] Crypt(byte[] encKey, byte[] data, bool encrypt)
        {
            Contract.Requires(encKey.Length == 16);
            Contract.Requires(data != null);

            Contract.Ensures(Contract.Result<byte[]>().Length == data.Length);

            var threeDesCbcEnc = new CbcBlockCipher(new DesEdeEngine());
            threeDesCbcEnc.Init(forEncryption: encrypt, parameters: new KeyParameter(encKey));
            return threeDesCbcEnc.ProcessMultipleBlocks(data);
        }

        internal static byte[] CalculateMAC(byte[] macKey, byte[] data)
        {
            Contract.Requires(macKey.Length == 16);
            Contract.Requires(data != null);

            Contract.Ensures(Contract.Result<byte[]>().Length == 8);

            var desMac3 = new ISO9797Alg3Mac(
                new DesEngine(),
                8*8, // 8 byte MAC length
                new ISO7816d4Padding() // equivalent to ISO 9797-1 scheme 2
            );
            desMac3.Init(new KeyParameter(macKey));
            return desMac3.Calculate(data);
        }

        internal static byte[] GetExternalAuthenticateData(
            byte[] encKey, byte[] macKey, byte[] icRnd, byte[] ifdRnd, byte[] ifdKey
        )
        {
            Contract.Requires(encKey.Length == 16);
            Contract.Requires(macKey.Length == 16);
            Contract.Requires(icRnd.Length == 8);
            Contract.Requires(ifdRnd.Length == 8);
            Contract.Requires(ifdKey.Length == 16);

            var s = new byte[32];
            Array.Copy(ifdRnd, 0, s, 0, 8);
            Array.Copy(icRnd, 0, s, 8, 8);
            Array.Copy(ifdKey, 0, s, 16, 16);

            // encrypt s
            byte[] ifdE = Crypt(encKey, s, encrypt: true);

            // calculate MAC of s
            byte[] mac = CalculateMAC(macKey, ifdE);

            var ret = new byte[40];
            Array.Copy(ifdE, 0, ret, 0, 32);
            Array.Copy(mac, 0, ret, 32, 8);
            return ret;
        }

        internal static ThreeDesSecuredReader ObtainSessionReader(
                IIsoReader reader, byte[] encKey, byte[] macKey, byte[] ifdKey, byte[] ifdRnd,
                byte[] extAuthResp
        )
        {
            Contract.Requires(encKey.Length == 16);
            Contract.Requires(macKey.Length == 16);
            Contract.Requires(ifdKey.Length == 16);
            Contract.Requires(ifdRnd.Length == 8);
            Contract.Requires(extAuthResp.Length == 40);

            byte[] respEnc = extAuthResp.Take(32).ToArray();
            byte[] respMac = extAuthResp.Skip(32).Take(8).ToArray();

            // recalculate MAC
            byte[] respMacCalc = CalculateMAC(macKey, respEnc);
            if (!respMac.SequenceEqual(respMacCalc))
            {
                throw new PassportCryptoException(
                    "verifying external authentication response",
                    "MAC verification failed"
                );
            }

            // decrypt and slice up
            byte[] respBytes = Crypt(encKey, respEnc, encrypt: false);
            byte[] icRnd = respBytes.Take(8).ToArray();
            byte[] ifdRndFromIc = respBytes.Skip(8).Take(8).ToArray();
            byte[] icKey = respBytes.Skip(16).Take(16).ToArray();

            if (!ifdRndFromIc.SequenceEqual(ifdRnd))
            {
                throw new PassportCryptoException(
                    "verifying external authentication response",
                    "passport returned our nonce incorrectly"
                );
            }

            byte[] sessionSeed = ifdKey
                .Zip(icKey, (ifdByte, icByte) => unchecked((byte)(ifdByte ^ icByte)))
                .ToArray();

            byte[] sessEncKey = Derive3DESKey(sessionSeed, 1);
            byte[] sessMacKey = Derive3DESKey(sessionSeed, 2);

            // obtain SSC (last 4B of icRnd ++ last 4B of ifdRnd)
            var ssc = new byte[8];
            Array.Copy(icRnd, 4, ssc, 0, 4);
            Array.Copy(ifdRnd, 4, ssc, 4, 4);

            // return encrypted reader
            return new ThreeDesSecuredReader(
                reader,
                sessEncKey, sessMacKey,
                ssc
            );
        }

        internal static ThreeDesSecuredReader Authenticate(MachineReadableZone mrz, IIsoReader reader)
        {
            // get nonce
            byte[] icRnd = RequestNonce(reader);

            // generate our values
            var ifdRnd = new byte[8];
            var ifdKey = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ifdRnd);
                rng.GetBytes(ifdKey);
            }

            // derive key from MRZ
            (byte[] encKey, byte[] macKey) = DeriveKeysFromMRZ(mrz);

            // calculate EXTERNAL AUTHENTICATE data
            var extAuthData = GetExternalAuthenticateData(encKey, macKey, icRnd, ifdRnd, ifdKey);

            // send
            byte[] respData;
            {
                var authCmd = new CommandApdu(IsoCase.Case4Short, reader.ActiveProtocol)
                {
                    CLA = 0x00,
                    Instruction = InstructionCode.ExternalAuthenticate,
                    P1 = 0x00, // no info about algorithm
                    P2 = 0x00, // no info about reference data
                    Data = extAuthData,
                    Le = 40,
                };
                Response authResp = reader.Transmit(authCmd);
                if (authResp.StatusWord != 0x9000)
                {
                    throw new PassportCommunicationException(
                        "performing authentication during basic access control",
                        authResp.StatusWord
                    );
                }
                respData = authResp.GetData();
            }

            // verify MAC and derive session keys
            return ObtainSessionReader(
                reader, encKey, macKey, ifdKey, ifdRnd, respData
            );
        }
    }
}
