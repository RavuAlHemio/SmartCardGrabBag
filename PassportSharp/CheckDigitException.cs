using System;

namespace PassportSharp
{
    public class CheckDigitException : Exception
    {
        public string CheckDigitType { get; }
        public int ReadCheckDigit { get; }
        public int CalculatedCheckDigit { get; }

        public CheckDigitException(string checkDigitType, int readCheckDigit, int calculatedCheckDigit)
            : base($"invalid {checkDigitType}: read {readCheckDigit}, calculated {calculatedCheckDigit}")
        {
            CheckDigitType = checkDigitType;
            ReadCheckDigit = readCheckDigit;
            CalculatedCheckDigit = calculatedCheckDigit;
        }

        public static void ThrowIfNotEqual(string checkDigitType, int readCheckDigit, int calculatedCheckDigit)
        {
            if (readCheckDigit != calculatedCheckDigit)
            {
                throw new CheckDigitException(checkDigitType, readCheckDigit, calculatedCheckDigit);
            }
        }
    }
}
