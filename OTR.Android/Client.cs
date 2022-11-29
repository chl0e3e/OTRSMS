using OTR.Android.Interop;
using System;
using System.Runtime.InteropServices;

namespace OTR.Android
{
    public class Client
    {
        static Client()
        {
            uint errorCode = LibOTR.Init(LibOTR.OTRL_VERSION_MAJOR, LibOTR.OTRL_VERSION_MINOR, LibOTR.OTRL_VERSION_SUB);
            GPGError error = new GPGError(errorCode);

            Console.WriteLine("[OTR] Initialised - " + error.Code);
        }

        public User User;

        public Client()
        {
            User = new User();
        }

        ~Client()
        {
            User = null;
        }
    }
}
