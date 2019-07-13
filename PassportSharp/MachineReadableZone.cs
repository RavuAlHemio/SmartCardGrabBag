using System;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Text;

namespace PassportSharp
{
    public class MachineReadableZone
    {
        public const char FillerCharacter = '<';

        public string DocumentType { get; set; }

        public string Issuer { get; set; }

        public string PrimaryIdentifier { get; set; }

        // nullable
        public string SecondaryIdentifier { get; set; }

        public bool NameMightBeTruncated { get; set; }

        public string DocumentNumber { get; set; }

        public string HolderNationality { get; set; }

        public string DateOfBirth { get; set; }

        public char Sex { get; set; }

        public string DateOfExpiry { get; set; }

        public string OptionalData1 { get; set; }

        // nullable, null on non-TD1 documents
        public string OptionalData2 { get; set; }

        public static MachineReadableZone Parse(string text)
        {
            string[] lines = text.Split("\n")
                .Select(ln => ln.Trim())
                .ToArray();

            if (lines.Length == 2 && lines.All(ln => ln.Length == 44))
            {
                // TD3 (e.g. passport)
                return ParseTD3(lines[0], lines[1]);
            }
            else if (lines.Length == 3 && lines.All(ln => ln.Length == 30))
            {
                // TD1 (credit card size)
                return ParseTD1(lines[0], lines[1], lines[2]);
            }
            else if (lines.Length == 2 && lines.All(ln => ln.Length == 36))
            {
                // TD2 (the pointless format)
                return ParseTD2(lines[0], lines[1]);
            }

            throw new FormatException("unknown MRZ format");
        }

        private static MachineReadableZone ParseTD3(string topLine, string bottomLine)
        {
            string documentType = topLine.Substring(0, 2).TrimEnd(FillerCharacter);
            string issuer = topLine.Substring(2, 3).TrimEnd(FillerCharacter);

            string fullName = topLine.Substring(5, 39).TrimEnd(FillerCharacter);
            bool mightTrunc = (fullName.Length == 39);
            (string priIdent, string secIdent) = SplitNameIntoIdentifiers(fullName);

            string docNumber = bottomLine.Substring(0, 9).TrimEnd(FillerCharacter);
            int checkDocNumber = bottomLine[9] - '0';
            string nationality = bottomLine.Substring(10, 3).TrimEnd(FillerCharacter);
            string dob = bottomLine.Substring(13, 6); // no trimming
            int checkDob = bottomLine[19] - '0';
            char sex = bottomLine[20];
            string expiry = bottomLine.Substring(21, 6); // no trimming
            int checkExpiry = bottomLine[27] - '0';
            string optData1 = bottomLine.Substring(28, 14).TrimEnd(FillerCharacter);
            int? checkOptData1 = (bottomLine[42] == FillerCharacter)
                ? (int?)null
                : (bottomLine[42] - '0');
            int compoCheck = bottomLine[43] - '0';

            // verify check digits
            int calcCheckDocNumber = CalculateCheckDigit(bottomLine.Substring(0, 9));
            int calcCheckDob = CalculateCheckDigit(bottomLine.Substring(13, 6));
            int calcCheckExpiry = CalculateCheckDigit(bottomLine.Substring(21, 6));
            int calcCheckOptData1 = CalculateCheckDigit(bottomLine.Substring(28, 14));
            int calcCompoCheck = CalculateCheckDigit(
                bottomLine.Substring(0, 10)
                + bottomLine.Substring(13, 7)
                + bottomLine.Substring(21, 22)
            );
            CheckDigitException.ThrowIfNotEqual("document number check digit", checkDocNumber, calcCheckDocNumber);
            CheckDigitException.ThrowIfNotEqual("date-of-birth check digit", checkDob, calcCheckDob);
            CheckDigitException.ThrowIfNotEqual("date-of-expiry check digit", checkExpiry, calcCheckExpiry);
            if (checkOptData1.HasValue)
            {
                CheckDigitException.ThrowIfNotEqual("optional data 1 check digit", checkOptData1.Value, calcCheckOptData1);
            }
            CheckDigitException.ThrowIfNotEqual("composite check digit", compoCheck, calcCompoCheck);

            return new MachineReadableZone
            {
                DocumentType = documentType,
                Issuer = issuer,
                PrimaryIdentifier = priIdent,
                SecondaryIdentifier = secIdent,
                NameMightBeTruncated = mightTrunc,
                DocumentNumber = docNumber,
                HolderNationality = nationality,
                DateOfBirth = dob,
                Sex = sex,
                DateOfExpiry = expiry,
                OptionalData1 = optData1,
                OptionalData2 = null,
            };
        }

        private static MachineReadableZone ParseTD1(string topLine, string middleLine, string bottomLine)
        {
            string documentType = topLine.Substring(0, 2).TrimEnd(FillerCharacter);
            string issuer = topLine.Substring(2, 3).TrimEnd(FillerCharacter);
            string docNumber = topLine.Substring(5, 9).TrimEnd(FillerCharacter);
            int checkDocNumber;
            string optData1;
            if (topLine[14] == FillerCharacter)
            {
                // truncated document number!
                int docNumberEnd = topLine.IndexOf(FillerCharacter, 15);
                if (docNumberEnd == -1)
                {
                    // doc number fills rest of available space
                    docNumber += topLine.Substring(15, (30 - 15) - 1);
                    checkDocNumber = topLine[30 - 1] - '0';
                    optData1 = null;
                }
                else
                {
                    docNumber += topLine.Substring(15, (docNumberEnd - 15) - 1);
                    checkDocNumber = topLine[docNumberEnd - 1] - '0';
                    optData1 = topLine.Substring(docNumberEnd + 1, (30 - docNumberEnd) - 1).TrimEnd(FillerCharacter);
                }
            }
            else
            {
                checkDocNumber = topLine[14] - '0';
                optData1 = topLine.Substring(15, 30 - 15).TrimEnd(FillerCharacter);
            }

            string dob = middleLine.Substring(0, 6); // no trimming
            int checkDob = middleLine[6] - '0';
            char sex = middleLine[7];
            string expiry = middleLine.Substring(8, 6); // no trimming
            int checkExpiry = middleLine[14] - '0';
            string nationality = middleLine.Substring(15, 3).TrimEnd(FillerCharacter);
            string optData2 = middleLine.Substring(18, 11).TrimEnd(FillerCharacter);
            int compoCheck = middleLine[29] - '0';

            string fullName = bottomLine.Substring(0, 30).TrimEnd(FillerCharacter);
            bool mightTrunc = (fullName.Length == 30);
            (string priIdent, string secIdent) = SplitNameIntoIdentifiers(fullName);

            // verify check digits
            int calcCheckDocNumber;
            if (topLine[14] == FillerCharacter)
            {
                // less simple (multi-field) calculation
                var fullDocNumber = new StringBuilder();
                fullDocNumber.Append(topLine, 5, 9);
                // start at 15 + 1 because we always look back one
                for (int i = 15 + 1; i < topLine.Length; ++i)
                {
                    if (topLine[i] == FillerCharacter)
                    {
                        // do not append the previous digit; it is the check digit
                        break;
                    }
                    fullDocNumber.Append(topLine[i - 1]);
                }
                calcCheckDocNumber = CalculateCheckDigit(fullDocNumber.ToString());
            }
            else
            {
                // simple calculation
                calcCheckDocNumber = CalculateCheckDigit(topLine.Substring(5, 9));
            }
            int calcCheckDob = CalculateCheckDigit(middleLine.Substring(0, 6));
            int calcCheckExpiry = CalculateCheckDigit(middleLine.Substring(8, 6));
            int calcCompoCheck = CalculateCheckDigit(
                topLine.Substring(5, 25)
                + middleLine.Substring(0, 7)
                + middleLine.Substring(8, 7)
                + middleLine.Substring(18, 11)
            );
            CheckDigitException.ThrowIfNotEqual("document number check digit", checkDocNumber, calcCheckDocNumber);
            CheckDigitException.ThrowIfNotEqual("date-of-birth check digit", checkDob, calcCheckDob);
            CheckDigitException.ThrowIfNotEqual("date-of-expiry check digit", checkExpiry, calcCheckExpiry);
            CheckDigitException.ThrowIfNotEqual("composite check digit", compoCheck, calcCompoCheck);

            return new MachineReadableZone
            {
                DocumentType = documentType,
                Issuer = issuer,
                PrimaryIdentifier = priIdent,
                SecondaryIdentifier = secIdent,
                NameMightBeTruncated = mightTrunc,
                DocumentNumber = docNumber,
                HolderNationality = nationality,
                DateOfBirth = dob,
                Sex = sex,
                DateOfExpiry = expiry,
                OptionalData1 = optData1,
                OptionalData2 = optData2,
            };
        }

        private static MachineReadableZone ParseTD2(string topLine, string bottomLine)
        {
            string documentType = topLine.Substring(0, 2).TrimEnd(FillerCharacter);
            string issuer = topLine.Substring(2, 3).TrimEnd(FillerCharacter);

            string fullName = topLine.Substring(5, 31).TrimEnd(FillerCharacter);
            bool mightTrunc = (fullName.Length == 31);
            (string priIdent, string secIdent) = SplitNameIntoIdentifiers(fullName);

            string docNumber = bottomLine.Substring(0, 9).TrimEnd(FillerCharacter);
            int checkDocNumber;
            string optData1;
            if (bottomLine[9] == FillerCharacter)
            {
                // truncated document number!
                int docNumberEnd = bottomLine.IndexOf(FillerCharacter, 28);
                if (docNumberEnd == -1)
                {
                    // doc number fills rest of available space
                    docNumber += bottomLine.Substring(28, (35 - 28) - 1);
                    checkDocNumber = bottomLine[35 - 1] - '0';
                    optData1 = null;
                }
                else
                {
                    docNumber += bottomLine.Substring(28, (docNumberEnd - 28) - 1);
                    checkDocNumber = bottomLine[docNumberEnd - 1] - '0';
                    optData1 = bottomLine.Substring(docNumberEnd + 1, (35 - docNumberEnd) - 1).TrimEnd(FillerCharacter);
                }
            }
            else
            {
                checkDocNumber = bottomLine[9] - '0';
                optData1 = bottomLine.Substring(28, 35 - 28).TrimEnd(FillerCharacter);
            }
            string nationality = bottomLine.Substring(10, 3).TrimEnd(FillerCharacter);
            string dob = bottomLine.Substring(13, 6); // no trimming
            int checkDob = bottomLine[19] - '0';
            char sex = bottomLine[20];
            string expiry = bottomLine.Substring(21, 6); // no trimming
            int checkExpiry = bottomLine[27] - '0';
            int compoCheck = bottomLine[35] - '0';

            // verify check digits
            int calcCheckDocNumber;
            if (bottomLine[9] == FillerCharacter)
            {
                var fullDocNumber = new StringBuilder();
                fullDocNumber.Append(bottomLine, 0, 9);
                for (int i = 28 + 1; i < bottomLine.Length; ++i)
                {
                    if (bottomLine[i] == FillerCharacter)
                    {
                        // do not append the previous digit; it is the check digit
                        break;
                    }
                    fullDocNumber.Append(bottomLine[i - 1]);
                }
                calcCheckDocNumber = CalculateCheckDigit(fullDocNumber.ToString());
            }
            else
            {
                calcCheckDocNumber = CalculateCheckDigit(bottomLine.Substring(0, 9));
            }
            int calcCheckDob = CalculateCheckDigit(bottomLine.Substring(13, 6));
            int calcCheckExpiry = CalculateCheckDigit(bottomLine.Substring(21, 6));
            int calcCompoCheck = CalculateCheckDigit(
                bottomLine.Substring(0, 10)
                + bottomLine.Substring(13, 7)
                + bottomLine.Substring(21, 14)
            );
            CheckDigitException.ThrowIfNotEqual("document number check digit", checkDocNumber, calcCheckDocNumber);
            CheckDigitException.ThrowIfNotEqual("date-of-birth check digit", checkDob, calcCheckDob);
            CheckDigitException.ThrowIfNotEqual("date-of-expiry check digit", checkExpiry, calcCheckExpiry);
            CheckDigitException.ThrowIfNotEqual("composite check digit", compoCheck, calcCompoCheck);

            return new MachineReadableZone
            {
                DocumentType = documentType,
                Issuer = issuer,
                PrimaryIdentifier = priIdent,
                SecondaryIdentifier = secIdent,
                NameMightBeTruncated = mightTrunc,
                DocumentNumber = docNumber,
                HolderNationality = nationality,
                DateOfBirth = dob,
                Sex = sex,
                DateOfExpiry = expiry,
                OptionalData1 = optData1,
                OptionalData2 = null,
            };
        }

        public static int CalculateCheckDigit(string data)
        {
            // ICAO 9303 Part 3 Section 4.9
            int[] weights = {7, 3, 1};

            int runningCheck = 0;
            for (int i = 0; i < data.Length; ++i)
            {
                char c = data[i];
                int cValue = CharToCheckDigitValue[c];
                int cWeight = weights[i % weights.Length];
                runningCheck = (runningCheck + (cValue * cWeight)) % 10;
            }
            return runningCheck;
        }

        private static (string PrimaryIdentifier, string SecondaryIdentifier) SplitNameIntoIdentifiers(string fullName)
        {
            int separatorIndex = fullName.IndexOf(NameIdentifierSeparator);
            if (separatorIndex == -1)
            {
                return (
                    fullName,
                    null
                );
            }
            else
            {
                return (
                    fullName.Substring(0, separatorIndex),
                    fullName.Substring(separatorIndex + 2)
                );
            }
        }

        private static string Inv(FormattableString fs) => fs.ToString(CultureInfo.InvariantCulture);

        private static readonly ImmutableDictionary<char, int> CharToCheckDigitValue;
        private static readonly string NameIdentifierSeparator = ("" + FillerCharacter + FillerCharacter);

        static MachineReadableZone()
        {
            // check digit values: ICAO 9303 Part 3 Section 4.9
            var builder = ImmutableDictionary.CreateBuilder<char, int>();
            builder[FillerCharacter] = 0;
            for (char c = '0'; c <= '9'; ++c)
            {
                // digits are themselves
                builder[c] = c - '0';
            }
            for (char c = 'A'; c <= 'Z'; ++c)
            {
                // letters are their alphabetical index + 10
                builder[c] = c - 'A' + 10;
            }
            CharToCheckDigitValue = builder.ToImmutable();
        }
    }
}
