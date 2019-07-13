using System;
using System.Collections.Generic;
using Xunit;
using PassportSharp;

namespace PassportSharpTests
{
    public class ByteIncrementTests
    {
        static void TestIncrement(params byte[] unincrementedIncremented)
        {
            var incrementMe = new byte[unincrementedIncremented.Length/2];
            var incremented = new byte[unincrementedIncremented.Length/2];
            Array.Copy(unincrementedIncremented, 0, incrementMe, 0, unincrementedIncremented.Length/2);
            Array.Copy(unincrementedIncremented, unincrementedIncremented.Length/2, incremented, 0, unincrementedIncremented.Length/2);

            incrementMe.Increment();

            Assert.Equal(
                (IEnumerable<byte>)incremented,
                (IEnumerable<byte>)incrementMe
            );
        }

        [Fact]
        public void TestIncrementZero()
        {
            TestIncrement(
                0x00,
                0x01
            );

            TestIncrement(
                0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01
            );
        }

        [Fact]
        public void TestIncrementNoCarry()
        {
            TestIncrement(
                0x12, 0x34, 0x56, 0x78,
                0x12, 0x34, 0x56, 0x79
            );
        }

        [Fact]
        public void TestIncrementSimpleCarry()
        {
            TestIncrement(
                0x00, 0x00, 0x00, 0xff,
                0x00, 0x00, 0x01, 0x00
            );

            TestIncrement(
                0x12, 0x34, 0x56, 0xff,
                0x12, 0x34, 0x57, 0x00
            );
        }

        [Fact]
        public void TestIncrementCarryWaterfall()
        {
            TestIncrement(
                0x00, 0x00, 0xff, 0xff,
                0x00, 0x01, 0x00, 0x00
            );

            TestIncrement(
                0x12, 0x34, 0x56, 0xff, 0xff,
                0x12, 0x34, 0x57, 0x00, 0x00
            );
        }

        [Fact]
        public void TestIncrementOverflow()
        {
            TestIncrement(
                0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00
            );

            TestIncrement(
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            );
        }
    }
}
