using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using OTR.Android.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace OTR.Android
{
    public class Operations
    {
        private static int GUID_SIZE_IN_BYTES = 16;

        private static Guid GuidFromOpaque(IntPtr opaqueData)
        {
            byte[] managedGuidBytes = new byte[GUID_SIZE_IN_BYTES];
            Marshal.Copy(opaqueData, managedGuidBytes, 0, GUID_SIZE_IN_BYTES);
            return new Guid(managedGuidBytes);
        }

        private LibOTR.MessageOps _ops;
        private Dictionary<Guid, Handler> _handlers;

        public bool ConvertMessages = false;
        public bool ResentMessagePrefixes = false;
        public bool ExtraSymmetricKeys = false;

        public interface Handler
        {
            public LibOTR.FragmentPolicy Policy(Context context);
            public void CreatePrivateKey(string accountName, string protocol);
            public LibOTR.LoggedInStatus LoggedIn(string accountName, string protocol, string recipient);
            public void InjectMessage(string accountName, string protocol, string recipient, string message);
            public void UpdateContextList();
            public void NewFingerprint(User user, string accountName, string protocol, string username, char[] fingerprint);
            public void WriteFingerprints();
            public void GoneSecure(Context context);
            public void GoneInsecure(Context context);
            public void StillSecure(Context context, LibOTR.Initiated isReply);
            public int MaxMessageSize(Context context);
            public void ReceivedSymmetricKey(Context context, uint use, byte[] useData, byte[] symmetricKey);
            public string ErrorMessage(Context context, LibOTR.ErrorCode error);
            public string ResentMessagePrefix(Context context);
            public void HandleSMPEvent(LibOTR.SMPEvent smpEvent, Context context, ushort progressPercent, string question);
            public void HandleMessageEvent(LibOTR.MessageEvent messageEvent, Context context, string message, GPGError error);
            public string ConvertMessage(Context context, LibOTR.ConvertType convertType, string source);
            public void TimerControl(uint interval);
        }

        public Operations()
        {
            this.SetupOps();
            this.SetupHandlers();
        }

        public void SetupOps()
        {
            _ops = new LibOTR.MessageOps();
            _ops.Policy = Policy;
            _ops.CreatePrivateKey = CreatePrivateKey;
            _ops.LoggedIn = LoggedIn;
            _ops.InjectMessage = InjectMessage;
            _ops.UpdateContextList = UpdateContextList;
            _ops.NewFingerprint = NewFingerprint;
            _ops.WriteFingerprints = WriteFingerprints;
            _ops.GoneSecure = GoneSecure;
            _ops.GoneInsecure = GoneInsecure;
            _ops.StillSecure = StillSecure;
            _ops.MaxMessageSize = MaxMessageSize;
            //_ops.AccountName = AccountName; // UNUSED
            //_ops.FreeAccountName = FreeAccountName; // UNUSED 
            if (this.ExtraSymmetricKeys)
            {
                _ops.ReceivedSymmetricKey = ReceivedSymmetricKey;
            }
            _ops.ErrorMessage = ErrorMessage;
            _ops.FreeErrorMessage = FreeErrorMessage;
            if (this.ResentMessagePrefixes)
            {
                _ops.ResentMessagePrefix = ResentMessagePrefix;
                _ops.FreeResentMessagePrefix = FreeResentMessagePrefix;
            }
            _ops.HandleSMPEvent = HandleSMPEvent;
            _ops.HandleMessageEvent = HandleMessageEvent;
            if (this.ConvertMessages)
            {
                _ops.ConvertMessage = ConvertMessage;
                _ops.FreeConvertedMessage = FreeConvertedMessage;
            }
            _ops.TimerControl = TimerControl;
        }

        public void SetupHandlers()
        {
            _handlers = new Dictionary<Guid, Handler>();
        }

        public void AddHandler(Guid guid, Handler handler)
        {
            this._handlers.Add(guid, handler);
        }

        public void RemoveHandler(Guid guid)
        {
            this._handlers.Remove(guid);
        }

        private uint Policy(IntPtr opaqueData, IntPtr context)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            return (uint) handler.Policy(managedContext);
        }

        private void CreatePrivateKey(IntPtr opaqueData, string accountName, string protocol)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            handler.CreatePrivateKey(accountName, protocol);
        }

        private int LoggedIn(IntPtr opaqueData, string accountName, string protocol, string recipient)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            return (int) handler.LoggedIn(accountName, protocol, recipient);
        }

        private void InjectMessage(IntPtr opaqueData, string accountName, string protocol, string recipient, string message)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            handler.InjectMessage(accountName, protocol, recipient, message);
        }

        private void UpdateContextList(IntPtr opaqueData)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            handler.UpdateContextList();
        }

        private void NewFingerprint(IntPtr opaqueData, IntPtr userState, string accountName, string protocol, string username, char[] fingerprint)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            User user = User.FromUnmanaged(userState);

            handler.NewFingerprint(user, accountName, protocol, username, fingerprint);
        }

        private void WriteFingerprints(IntPtr opaqueData)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            handler.WriteFingerprints();
        }

        private void GoneSecure(IntPtr opaqueData, IntPtr context)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            handler.GoneSecure(managedContext);
        }

        private void GoneInsecure(IntPtr opaqueData, IntPtr context)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            handler.GoneInsecure(managedContext);
        }

        private void StillSecure(IntPtr opaqueData, IntPtr context, int isReply)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            handler.StillSecure(managedContext, (LibOTR.Initiated) isReply);
        }

        private int MaxMessageSize(IntPtr opaqueData, IntPtr context)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            return handler.MaxMessageSize(managedContext);
        }

        /*
         * UNUSED
        private IntPtr AccountName(IntPtr opaqueData, IntPtr accountName, string protocol)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            return IntPtr.Zero;
        }

        private void FreeAccountName(IntPtr opaqueData, IntPtr accountName)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

        }
        */

        private void ReceivedSymmetricKey(IntPtr opaqueData, IntPtr context, uint use, IntPtr useData, uint useDataLen, IntPtr symmetricKey)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            byte[] managedUseData = new byte[useDataLen];
            byte[] managedSymmetricKey = new byte[LibOTR.OTRL_EXTRAKEY_BYTES];

            Marshal.Copy(useData, managedUseData, 0, (int) useDataLen);
            Marshal.Copy(symmetricKey, managedSymmetricKey, 0, (int) LibOTR.OTRL_EXTRAKEY_BYTES);

            handler.ReceivedSymmetricKey(managedContext, use, managedUseData, managedSymmetricKey);
        }

        private IntPtr ErrorMessage(IntPtr opaqueData, IntPtr context, uint otrErrorCode)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            string errorMessage = handler.ErrorMessage(managedContext, (LibOTR.ErrorCode)otrErrorCode);
            return Marshal.StringToHGlobalAuto(errorMessage);
        }

        private void FreeErrorMessage(IntPtr opaqueData, IntPtr errorMessage)
        {
            //Guid handlerGuid = GuidFromOpaque(opaqueData);
            //Handler handler = _handlers[handlerGuid];

            Marshal.FreeHGlobal(errorMessage);
        }

        private IntPtr ResentMessagePrefix(IntPtr opaqueData, IntPtr context)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            string resentPrefix = handler.ResentMessagePrefix(managedContext);
            return Marshal.StringToHGlobalAuto(resentPrefix);
        }

        private void FreeResentMessagePrefix(IntPtr opaqueData, IntPtr prefix)
        {
            //Guid handlerGuid = GuidFromOpaque(opaqueData);
            //Handler handler = _handlers[handlerGuid];

            Marshal.FreeHGlobal(prefix);
        }

        private void HandleSMPEvent(IntPtr opaqueData, uint smpEvent, IntPtr context, ushort progressPercent, string question)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            handler.HandleSMPEvent((LibOTR.SMPEvent) smpEvent, managedContext, progressPercent, question);
        }

        private void HandleMessageEvent(IntPtr opaqueData, uint messageEvent, IntPtr context, string message, uint error)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);
            GPGError gpgError = GPGError.Marshal(error);

            handler.HandleMessageEvent((LibOTR.MessageEvent) messageEvent, managedContext, message, gpgError);
        }

        private void ConvertMessage(IntPtr opaqueData, IntPtr context, uint convertType, out IntPtr dest, IntPtr src)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            string message = Marshal.PtrToStringAuto(src); // before convert
            string convertedMessage = handler.ConvertMessage(managedContext, (LibOTR.ConvertType) convertType, message);

            dest = Marshal.StringToHGlobalAuto(convertedMessage);
        }

        private void FreeConvertedMessage(IntPtr opaqueData, IntPtr context, IntPtr dest)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];
            Context managedContext = Context.FromPtr(context);

            Marshal.FreeHGlobal(dest);
        }

        private void TimerControl(IntPtr opaqueData, uint interval)
        {
            Guid handlerGuid = GuidFromOpaque(opaqueData);
            Handler handler = _handlers[handlerGuid];

            handler.TimerControl(interval);
        }
    }
}