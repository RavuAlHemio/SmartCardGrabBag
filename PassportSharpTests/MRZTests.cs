using System;
using Xunit;
using PassportSharp;

namespace PassportSharpTests
{
    public class MRZTests
    {
        [Fact]
        public void TestValidTD3Part4()
        {
            string mrzText =
                "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
                "\n" +
                "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("P", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
            Assert.Equal("ANNA<MARIA", mrz.SecondaryIdentifier);
            Assert.Equal("L898902C3", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("740812", mrz.DateOfBirth);
            Assert.Equal('F', mrz.Sex);
            Assert.Equal("120415", mrz.DateOfExpiry);
            Assert.Equal("ZE184226B", mrz.OptionalData1);
            Assert.Null(mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD1Part5()
        {
            string mrzText =
                "I<UTOD231458907<<<<<<<<<<<<<<<" +
                "\n" +
                "7408122F1204159UTO<<<<<<<<<<<6" +
                "\n" +
                "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
            Assert.Equal("ANNA<MARIA", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("740812", mrz.DateOfBirth);
            Assert.Equal('F', mrz.Sex);
            Assert.Equal("120415", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Equal("", mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD2Part6()
        {
            string mrzText =
                "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
                "\n" +
                "D231458907UTO7408122F1204159<<<<<<<6"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
            Assert.Equal("ANNA<MARIA", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("740812", mrz.DateOfBirth);
            Assert.Equal('F', mrz.Sex);
            Assert.Equal("120415", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Null(mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD2Part11Overlong()
        {
            string mrzText =
                "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<" +
                "\n" +
                "D23145890<UTO3407127M95071227349<<<8"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("STEVENSON", mrz.PrimaryIdentifier);
            Assert.Equal("PETER<JOHN", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890734", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("340712", mrz.DateOfBirth);
            Assert.Equal('M', mrz.Sex);
            Assert.Equal("950712", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Null(mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD2Part11Short()
        {
            string mrzText =
                "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
                "\n" +
                "L898902C<3UTO6908061F9406236<<<<<<<2"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
            Assert.Equal("ANNA<MARIA", mrz.SecondaryIdentifier);
            Assert.Equal("L898902C", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("690806", mrz.DateOfBirth);
            Assert.Equal('F', mrz.Sex);
            Assert.Equal("940623", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Null(mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD1Part11Overlong()
        {
            string mrzText =
                "I<UTOD23145890<7349<<<<<<<<<<<" +
                "\n" +
                "3407127M9507122UTO<<<<<<<<<<<2" +
                "\n" +
                "STEVENSON<<PETER<JOHN<<<<<<<<<"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("STEVENSON", mrz.PrimaryIdentifier);
            Assert.Equal("PETER<JOHN", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890734", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("340712", mrz.DateOfBirth);
            Assert.Equal('M', mrz.Sex);
            Assert.Equal("950712", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Equal("", mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD1Part11Short()
        {
            string mrzText =
                "I<UTOL898902C<3<<<<<<<<<<<<<<<" +
                "\n" +
                "6908061F9406236UTO<<<<<<<<<<<2" +
                "\n" +
                "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
            Assert.Equal("ANNA<MARIA", mrz.SecondaryIdentifier);
            Assert.Equal("L898902C", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("690806", mrz.DateOfBirth);
            Assert.Equal('F', mrz.Sex);
            Assert.Equal("940623", mrz.DateOfExpiry);
            Assert.Equal("", mrz.OptionalData1);
            Assert.Equal("", mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD1Part11OverlongAndMore()
        {
            string mrzText =
                "I<UTOD23145890<7349<SWAG<<<<<<" +
                "\n" +
                "3407127M9507122UTOYOLO<<<<<<<5" +
                "\n" +
                "STEVENSON<<PETER<JOHN<<<<<<<<<"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("STEVENSON", mrz.PrimaryIdentifier);
            Assert.Equal("PETER<JOHN", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890734", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("340712", mrz.DateOfBirth);
            Assert.Equal('M', mrz.Sex);
            Assert.Equal("950712", mrz.DateOfExpiry);
            Assert.Equal("SWAG", mrz.OptionalData1);
            Assert.Equal("YOLO", mrz.OptionalData2);
        }

        [Fact]
        public void TestValidTD2Part11OverlongAndMore()
        {
            string mrzText =
                "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<" +
                "\n" +
                "D23145890<UTO3407127M95071227349<XY9"
            ;

            var mrz = MachineReadableZone.Parse(mrzText);
            Assert.Equal("I", mrz.DocumentType);
            Assert.Equal("UTO", mrz.HolderNationality);
            Assert.Equal("STEVENSON", mrz.PrimaryIdentifier);
            Assert.Equal("PETER<JOHN", mrz.SecondaryIdentifier);
            Assert.Equal("D23145890734", mrz.DocumentNumber);
            Assert.Equal("UTO", mrz.Issuer);
            Assert.Equal("340712", mrz.DateOfBirth);
            Assert.Equal('M', mrz.Sex);
            Assert.Equal("950712", mrz.DateOfExpiry);
            Assert.Equal("XY", mrz.OptionalData1);
            Assert.Null(mrz.OptionalData2);
        }
    }
}
