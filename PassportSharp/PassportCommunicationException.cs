using System;

namespace PassportSharp
{
    public class PassportCommunicationException : Exception
    {
        public string ProcessDescription { get; }
        public int ResponseCode { get; }

        public PassportCommunicationException(string processDescription, int responseCode)
            : base($"response 0x{responseCode:X4} while {processDescription}")
        {
            ProcessDescription = processDescription;
            ResponseCode = responseCode;
        }
    }
}
