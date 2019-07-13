using System;

namespace PassportSharp
{
    public class PassportCryptoException : Exception
    {
        public string ProcessDescription { get; }
        public string ErrorDescription { get; }

        public PassportCryptoException(string processDescription, string errorDescription)
            : base($"{errorDescription} while {processDescription}")
        {
            ProcessDescription = processDescription;
            ErrorDescription = errorDescription;
        }
    }
}
