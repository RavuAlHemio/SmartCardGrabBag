using System;
using System.Collections.Generic;
using System.IO;

namespace SmartCardGrabBag
{
    public static class Hexy
    {
        static T[] TakeUpTo<T>(this IEnumerator<T> enumerator, int count)
        {
            var ret = new T[count];
            for (int i = 0; i < count; ++i)
            {
                if (!enumerator.MoveNext())
                {
                    // premature end of enumerator; return shortened array
                    var shortRet = new T[i];
                    Array.Copy(ret, 0, shortRet, 0, i);
                    return shortRet;
                }
                ret[i] = enumerator.Current;
            }
            return ret;
        }

        public static void PrintHexDump(IEnumerable<byte> bytes, TextWriter outWriter = null, string linePrefix = "", int bytesPerLine = 8)
        {
            if (outWriter == null)
            {
                outWriter = Console.Out;
            }

            long loc = 0;
            using (var rator = bytes.GetEnumerator())
            {
                for (;;)
                {
                    byte[] bs = rator.TakeUpTo(bytesPerLine);
                    if (bs.Length == 0)
                    {
                        return;
                    }

                    // position
                    outWriter.Write($"{linePrefix}{loc:x8}  ");

                    // hex bytes
                    for (int i = 0; i < bytesPerLine; ++i)
                    {
                        if (i < bs.Length)
                        {
                            outWriter.Write($"{bs[i]:x2} ");
                        }
                        else
                        {
                            outWriter.Write("   ");
                        }
                    }

                    outWriter.Write("  |");

                    // characters
                    for (int i = 0; i < bytesPerLine && i < bs.Length; ++i)
                    {
                        if (bs[i] >= 0x00 && bs[i] <= 0x1F)
                        {
                            outWriter.Write('.');
                        }
                        else if (bs[i] >= 0x7F && bs[i] <= 0x9F)
                        {
                            outWriter.Write('.');
                        }
                        else
                        {
                            outWriter.Write((char)bs[i]);
                        }
                    }

                    // including newline
                    outWriter.WriteLine("|");

                    loc += bytesPerLine;
                }
            }
        }

        public static void PrintBerTlvBlockDump(BerTlvBlock block, TextWriter outWriter = null, string linePrefix = "", int bytesPerLine = 8)
        {
            if (outWriter == null)
            {
                outWriter = Console.Out;
            }

            outWriter.WriteLine($"{linePrefix}{block.TagDescription}");
            if (block.Constructed)
            {
                // output subblocks recursively
                foreach (BerTlvBlock subBlock in block.SubBlocks)
                {
                    PrintBerTlvBlockDump(subBlock, outWriter, $"{linePrefix}  ", bytesPerLine);
                }
            }
            else
            {
                // hex-dump bytes
                PrintHexDump(block.RawBytes, outWriter, $"{linePrefix}  ", bytesPerLine);
            }
        }
    }
}
