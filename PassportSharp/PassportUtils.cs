using System;
using Org.BouncyCastle.Crypto;
using PCSC.Iso7816;

namespace PassportSharp
{
    public static class PassportUtils
    {
        public static byte[] Calculate(this IDigest digest, byte[] data, int offset = 0, int length = -1)
        {
            if (length == -1)
            {
                length = data.Length - offset;
            }

            digest.BlockUpdate(data, offset, length);
            var ret = new byte[digest.GetDigestSize()];
            digest.DoFinal(ret, 0);
            return ret;
        }

        public static byte[] Calculate(this IMac mac, byte[] data, int offset = 0, int length = -1)
        {
            if (length == -1)
            {
                length = data.Length - offset;
            }

            mac.BlockUpdate(data, offset, length);
            var ret = new byte[mac.GetMacSize()];
            mac.DoFinal(ret, 0);
            return ret;
        }

        public static byte[] ProcessMultipleBlocks(this IBlockCipher cipher, byte[] data, int offset = 0, int length = -1)
        {
            if (length == -1)
            {
                length = data.Length - offset;
            }

            if (length % cipher.GetBlockSize() != 0)
            {
                throw new ArgumentException($"length of {nameof(data)} ({length}) must be a multiple of the block size of {nameof(cipher)} ({cipher.GetBlockSize()})");
            }

            var ret = new byte[length];
            for (int i = 0; i < length; i += cipher.GetBlockSize())
            {
                cipher.ProcessBlock(data, offset + i, ret, i);
            }
            return ret;
        }

        public static void Increment(this byte[] bs)
        {
            for (int i = bs.Length - 1; i >= 0; --i)
            {
                byte newVal = unchecked((byte)(bs[i] + 1));
                if (newVal > bs[i])
                {
                    bs[i] = newVal;
                    // no carry
                    break;
                }

                bs[i] = newVal;
                // carry
            }
        }

        public static bool IsSendingData(this IsoCase isoCase)
        {
            switch (isoCase)
            {
                case IsoCase.Case1: // S=f, R=f
                case IsoCase.Case2Short: // S=f, R=t
                case IsoCase.Case2Extended:
                    return false;
                case IsoCase.Case3Short: // S=t, R=f
                case IsoCase.Case3Extended:
                case IsoCase.Case4Short: // S=t, R=t
                case IsoCase.Case4Extended:
                    return true;
                default:
                    throw new ArgumentOutOfRangeException(nameof(isoCase));
            }
        }

        public static bool IsReceivingData(this IsoCase isoCase)
        {
            switch (isoCase)
            {
                case IsoCase.Case1: // S=f, R=f
                case IsoCase.Case3Short: // S=t, R=f
                case IsoCase.Case3Extended:
                    return false;
                case IsoCase.Case2Short: // S=f, R=t
                case IsoCase.Case2Extended:
                case IsoCase.Case4Short: // S=t, R=t
                case IsoCase.Case4Extended:
                    return true;
                default:
                    throw new ArgumentOutOfRangeException(nameof(isoCase));
            }
        }
    }
}
