using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Systems;
using Android.Views;
using Android.Widget;
using Java.Lang.Reflect;
using Java.Util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Android.Content.Res.Resources;
using static Javax.Crypto.Spec.PSource;
using static OTR.Android.Interop.LibOTR;

namespace OTR.Android.Interop
{
    /// <summary>
    /// A C# implementation of libotr using Interop
    /// </summary>
    public class LibOTR
    {
        public static uint OTRL_VERSION_MAJOR = 4;
        public static uint OTRL_VERSION_MINOR = 1;
        public static uint OTRL_VERSION_SUB = 1;

        /// <summary>
        /// The length of an extra symmetric key used by the ReceivedSymmetricKey delegate.
        /// </summary>
        public static uint OTRL_EXTRAKEY_BYTES = 32;

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// - OTRL_ERRCODE_ENCRYPTION_ERROR
        /// 		occured while encrypting a message
        /// - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
        /// 		sent encrypted message to somebody who is not in
        /// 		a mutual OTR session
        /// - OTRL_ERRCODE_MSG_UNREADABLE
        ///		sent an unreadable encrypted message
        /// - OTRL_ERRCODE_MSG_MALFORMED
        /// 		message sent is malformed
        /// </summary>
        public enum ErrorCode
        {
            None = 0,
            EncryptionError = 1,
            MessageNotInPrivate = 2,
            MessageUnreadable = 3,
            MessageMalformed = 4
        }

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// - OTRL_SMPEVENT_ASK_FOR_SECRET
        ///      prompt the user to enter a shared secret. The sender application
        ///      should call otrl_message_initiate_smp, passing NULL as the question.
        ///      When the receiver application resumes the SM protocol by calling
        ///      otrl_message_respond_smp with the secret answer.
        /// - OTRL_SMPEVENT_ASK_FOR_ANSWER
        ///      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
        ///      otrl_message_initiate_smp_q instead)
        /// - OTRL_SMPEVENT_CHEATED
        ///      abort the current auth and update the auth progress dialog
        ///      with progress_percent. otrl_message_abort_smp should be called to
        ///      stop the SM protocol.
        /// - OTRL_SMPEVENT_INPROGRESS 	and
        ///   OTRL_SMPEVENT_SUCCESS 		and
        ///   OTRL_SMPEVENT_FAILURE    	and
        ///   OTRL_SMPEVENT_ABORT
        ///      update the auth progress dialog with progress_percent
        /// - OTRL_SMPEVENT_ERROR
        ///      (same as OTRL_SMPEVENT_CHEATED)
        /// </summary>
        public enum SMPEvent
        {
            None = 0,
            Error = 1,
            Abort = 2,
            Cheated = 3,
            AskForAnswer = 4,
            AskForSecret = 5,
            InProgress = 6,
            Success = 7,
            Failure = 8
        }

        /// <summary>
        /// An enum used to determine whether or not the user is logged in
        /// </summary>
        public enum LoggedInStatus
        {
            NotSure = -1,
            No = 0,
            Yes = 1
        }

        /// <summary>
        /// Who initiated the AKE
        /// </summary>
        public enum Initiated
        {
            Remote = 0,
            Local = 1
        }

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
        ///      Our policy requires encryption but we are trying to send
        ///      an unencrypted message out.
        /// - OTRL_MSGEVENT_ENCRYPTION_ERROR
        ///      An error occured while encrypting a message and the message
        ///      was not sent.
        /// - OTRL_MSGEVENT_CONNECTION_ENDED
        ///      Message has not been sent because our buddy has ended the
        ///      private conversation. We should either close the connection,
        ///      or refresh it.
        /// - OTRL_MSGEVENT_SETUP_ERROR
        ///      A private conversation could not be set up. A gcry_error_t
        ///      will be passed.
        /// - OTRL_MSGEVENT_MSG_REFLECTED
        ///      Received our own OTR messages.
        /// - OTRL_MSGEVENT_MSG_RESENT
        ///      The previous message was resent.
        /// - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
        ///      Received an encrypted message but cannot read
        ///      it because no private connection is established yet.
        /// - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
        ///      Cannot read the received message.
        /// - OTRL_MSGEVENT_RCVDMSG_MALFORMED
        ///      The message received contains malformed data.
        /// - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
        ///      Received a heartbeat.
        /// - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
        ///      Sent a heartbeat.
        /// - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
        ///      Received a general OTR error. The argument 'message' will
        ///      also be passed and it will contain the OTR error message.
        /// - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
        ///      Received an unencrypted message. The argument 'message' will
        ///      also be passed and it will contain the plaintext message.
        /// - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
        ///      Cannot recognize the type of OTR message received.
        /// - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
        ///      Received and discarded a message intended for another instance.
        /// </summary>
        public enum MessageEvent
        {
            None = 0,
            EncryptionRequired = 1,
            EncryptionError = 2,
            ConnectionEnded = 3,
            SetupError = 4,
            MessageReflected = 5,
            MessageResent = 5,
            ReceivedMessageNotInPrivate = 6,
            ReceivedMessageUnreadable = 7,
            ReceivedMessageMalformed = 8,
            HeartbeatReceived = 9,
            HeartbeatSent = 10,
            ReceivedMessageGeneralError = 11,
            ReceivedMessageUnencrypted = 12,
            ReceivedMessageUnrecognised = 13,
            ReceivedMessageForOtherInstance = 14
        }

        /// <summary>
        /// An enum declared in libotr-4.1.1/src/context.h for storing the current state of a context's conversation
        /// </summary>
        public enum MessageState
        {
            Plaintext = 0,
            Encrypted = 1,
            Finished = 2
        }

        /// <summary>
        /// ConvertMessage
        /// Called immediately before a data message is encrypted, and after a data
        /// message is decrypted.The OtrlConvertType parameter has the value
        /// OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
        /// cases.
        /// </summary>
        public enum ConvertType
        {
            Sending = 0,
            Receiving = 1
        }

        public enum FragmentPolicy
        {
            SendSkip = 0,
            SendAll = 1,
            SendAllButFirst = 2,
            SendAllButLast = 3
        }

        public enum AuthState
        {
            None = 0,
            AwaitingDHKey = 1,
            AwaitingRevealSignature = 2,
            AwaitingSignature = 3,
            V1Setup = 4
        }

        /* Code Design: Start parameters on a new line when they contain MarshalAs attributes */

        /// <summary>
        /// libotr-4.1.1/src/proto.h:
        /// 
        /// Initialize the OTR library.  Pass the version of libotr you are
        /// using.
        /// </summary>
        /// <param name="major">libotr major version number</param>
        /// <param name="minor">libotr minor version number</param>
        /// <param name="sub">libotr sub-version number</param>
        /// <returns></returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_init", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Init(uint major,
            uint minor,
            uint sub);

        /// <summary>
        /// Free a OtrlUserState.  If you have a timer running for this userstate,
        /// stop it before freeing the userstate.
        /// </summary>
        /// <returns>pointer to OtrlUserState to be marshalled into LibOTR.UserState</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_userstate_create", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CreateUserState();

        /// <summary>
        /// libotr-4.1.1/src/userstate.h:
        /// 
        /// Create a new OtrlUserState.  Most clients will only need one of
        /// these.A OtrlUserState encapsulates the list of known fingerprints
        /// and the list of private keys; if you have separate files for these
        /// things for (say) different users, use different OtrlUserStates.If
        /// you've got only one user, with multiple accounts all stored together
        /// in the same fingerprint store and privkey store files, use just one
        /// OtrlUserState.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_userstate_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeUserState(IntPtr userState);

        /// <summary>
        /// libotr-4.1.1/src/privkey.h:
        /// 
        /// Read a sets of private DSA keys from a file on disk into the given
        /// OtrlUserState
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="file">File path of the private key data</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError. For more information see LibGPGError</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_privkey_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadPrivateKey(IntPtr userState,
            [MarshalAs(UnmanagedType.LPStr)] string file);

        /// <summary>
        /// libotr-4.1.1/src/instag.h:
        /// 
        /// Read our instance tag from a file on disk into the given
        /// OtrlUserState.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="file">File path of the instance tag data</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError. For more information see LibGPGError</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_instag_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadInstanceTags(IntPtr userState,
            [MarshalAs(UnmanagedType.LPStr)] string file);

        /// <summary>
        /// ConnContextCallback will be called when a new `ConnContext` is created.
        /// It will also pass back some application-specific data.
        /// </summary>
        /// <param name="callbackData">Application data passed in earlier and returned by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ConnContextCallback(IntPtr callbackData, IntPtr context);

        /// <summary>
        /// libotr-4.1.1/src/privkey.h:
        /// 
        /// Read the fingerprint store from a file on disk into the given
        /// OtrlUserState.
        /// 
        /// callback is a function that will be called in the event that a new ConnContext is
        /// created.  It will be passed the data that you supplied, as well as a
        /// pointer to the new ConnContext.  You can use this to add
        /// application-specific information to the ConnContext using the
        /// "context->app" field, for example.  If you don't need to do this, you
        /// can pass NULL for the last two arguments of SendMessage.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="file">File path of the private key fingerprints</param>
        /// <param name="callback">Delegate to return with application data and a new `ConnContext` created by libotr</param>
        /// <param name="callbackData">Application data passed in earlier and returned by libotr</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError..</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_privkey_read_fingerprints", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ReadPrivateKeyFingerprints(IntPtr userState,
            [MarshalAs(UnmanagedType.LPStr)] string file,
            IntPtr callback,
            IntPtr callbackData);

        /// <summary>
        /// libotr-4.1.1/src/userstate.h:
        /// 
        /// An OtrlUserState encapsulates the list of known fingerprints
        /// and the list of private keys; if you have separate files for these
        /// things for (say) different users, use different OtrlUserStates. If
        /// you've got only one user, with multiple accounts all stored together
        /// in the same fingerprint store and private key store files, use just one
        /// OtrlUserState.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct UserState
        {
            IntPtr ContextRoot;
            IntPtr PrivKeyRoot;
            IntPtr InstanceTagRoot;
            IntPtr PendingRoot;
            int TimerRunning;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Fingerprint
        {
            IntPtr Next;
            IntPtr ToUs;
            IntPtr AsString;
            IntPtr Context;
            IntPtr Trust;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Context
        {
            /// <summary>
            /// The next item in the linked list
            /// </summary>
            IntPtr Next;
            /// <summary>
            /// A pointer to the pointer to us
            /// </summary>
            IntPtr ToUs;
            /// <summary>
            /// Private context pointer used internally by LibOTR
            /// </summary>
            IntPtr ContextPriv;
            [MarshalAs(UnmanagedType.LPStr)] string username;
            [MarshalAs(UnmanagedType.LPStr)] string accountName;
            [MarshalAs(UnmanagedType.LPStr)] string protocol;
            IntPtr MasterContext;
            IntPtr RecentReceivedChild;
            IntPtr RecentSentChild;
            IntPtr RecentChild;
            uint LocalInstance;
            uint RemoteInstance;
            uint MessageState;

        }

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Return the OTR policy for the given context.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError. For more information see LibGPGError.</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate uint Policy(IntPtr opaqueData, IntPtr context);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Create a private key for the given accountname/protocol if
        /// desired.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="accountName">Account name used to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CreatePrivateKey(IntPtr opaqueData,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Report whether you think the given user is online. 
        /// 
        /// If you return 1, messages such as heartbeats or other
        /// notifications may be sent to the user, which could result in "not
        /// logged in" errors if you're wrong.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="accountName">Account name used internally to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        /// <param name="recipient">Recipient used to identify their account using OTR</param>
        /// <returns>Return 1 if you think the recipient is, 0 if you think they aren't, and -1 if you're not sure. Returning 1 could cause problems if the user is online, and may cause errors in your application.</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int LoggedIn(IntPtr opaqueData,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol,
            [MarshalAs(UnmanagedType.LPStr)] string recipient);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Send the given IM to the given recipient from the given
        /// accountname/protocol. This is used to inject the encrypted
        /// data, OTR handshakes and OTR heartbeats into the message stream.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="accountName">Account name used to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        /// <param name="recipient">Recipient used to identify a user that isn't you using OTR</param>
        /// <param name="message">Message to send from libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void InjectMessage(IntPtr opaqueData,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol,
            [MarshalAs(UnmanagedType.LPStr)] string recipient,
            [MarshalAs(UnmanagedType.LPStr)] string message);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// When the list of ConnContexts changes (including a change in
        /// state), this is called so the UI can be updated.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void UpdateContextList(IntPtr opaqueData);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// A new fingerprint for the given user has been received.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="userState">Pointer to the user state created by CreateUserState()</param>
        /// <param name="accountName">Account name used to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        /// <param name="username">Username used to identify a user that isn't you using OTR</param>
        /// <param name="fingerprint">An LPSTR pointing to a user that isn't you's new fingerprint. WARNING: The fingerprint must be 20 characters.</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NewFingerprint(IntPtr opaqueData,
            IntPtr userState,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol,
            [MarshalAs(UnmanagedType.LPStr)] string username,
            [MarshalAs(UnmanagedType.LPStr)] char[] fingerprint);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// The list of known fingerprints has changed.  Write them to disk.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void WriteFingerprints(IntPtr opaqueData);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// A ConnContext has entered a secure state.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void GoneSecure(IntPtr opaqueData, IntPtr context);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// A ConnContext has left a secure state.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void GoneInsecure(IntPtr opaqueData, IntPtr context);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// We have completed an authentication, using the D-H keys we
        /// already knew. is_reply indicates whether we initiated the AKE.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="isReply">Returns true if we initiated the AKE</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void StillSecure(IntPtr opaqueData, IntPtr context, int isReply);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Find the maximum message size supported by this protocol.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <returns>The maximum message size supported by the application's protocol</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int MaxMessageSize(IntPtr opaqueData, IntPtr context);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// WARNING: LIBOTR MARKS THIS FUNCTION AS UNUSED. DO NOT USE IT. (v4.1.1)
        /// 
        /// Return a newly allocated string containing a human-friendly
        /// representation for the given account.
        /// Should be deallocated with FreeAccountName
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="accountName">LPSTR which contains the human-friendly account name</param>
        /// <param name="protocol">Protocol which the account is using</param>
        /// <returns>LPSTR to a new account name</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr AccountName(IntPtr opaqueData, IntPtr accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// WARNING: LIBOTR MARKS THIS FUNCTION AS UNUSED. DO NOT USE IT. (v4.1.1)
        /// 
        /// Deallocate a string returned by account_name
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="accountName">LPSTR which contains the human-friendly account name</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void FreeAccountName(IntPtr opaqueData,
            IntPtr accountName);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// We received a request from the buddy to use the current "extra"
        /// symmetric key.  The key will be passed in symmetricKey, of length
        /// OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
        /// data will be passed so that the applications can communicate other
        /// information (some id for the data transfer, for example).
        /// 
        /// UPGRADING:
        /// 
        /// This is called when a remote buddy has specified a use for the current
        /// symmetric key. If your application does not use the extra symmetric key
        /// it does not need to provide an implementation for this operation.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="use">Unsigned-integer passed back for the application by libotr which denotes the requested use of the key</param>
        /// <param name="useData">Data specific to the key's use passed back for the application</param>
        /// <param name="useDataLen">Length of the data passed back</param>
        /// <param name="symmetricKey">A pointer which is the location of the symmetric key, of length OTRL_EXTRAKEY_BYTES</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ReceivedSymmetricKey(IntPtr opaqueData,
            IntPtr context,
            uint use,
            IntPtr useData,
            uint useDataLen,
            IntPtr symmetricKey);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Return a string according to the error event. This string will then
        /// be concatenated to an OTR header to produce an OTR protocol error
        /// message. The error code should be converted to the LibOTR.ErrorCode
        /// enum. The error string can be free'd by FreeErrorMessage.
        /// 
        /// The following are the possible error events:
        /// 
        /// - OTRL_ERRCODE_ENCRYPTION_ERROR
        /// 		occured while encrypting a message
        /// - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
        /// 		sent encrypted message to somebody who is not in
        /// 		a mutual OTR session
        /// - OTRL_ERRCODE_MSG_UNREADABLE
        ///		sent an unreadable encrypted message
        /// - OTRL_ERRCODE_MSG_MALFORMED
        /// 		message sent is malformed
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="otrErrorCode">An unsigned-integer error code to be cast to a LibOTR.ErrorCode</param>
        /// <returns>An LPSTR pointing to the error message for the given error code</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ErrorMessage(IntPtr opaqueData, IntPtr context, uint otrErrorCode);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Deallocate a string returned by otr_error_message
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="errorMessage">A pointer to the error message you returned in ErrorMessage</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void FreeErrorMessage(IntPtr opaqueData, IntPtr errorMessage);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Return a string that will be prefixed to any resent message. If this
        /// function is not provided by the application then the default prefix,
        /// "[resent]", will be used.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <returns>An LPSTR pointing to the resent message's prefix</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ResentMessagePrefix(IntPtr opaqueData, IntPtr context);


        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Deallocate a string returned by resent_msg_prefix
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="prefix">A pointer to the prefix you allocated in ResentMessagePrefix</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void FreeResentMessagePrefix(IntPtr opaqueData, IntPtr prefix);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        ///
        /// These are the possible events:
        /// - OTRL_SMPEVENT_ASK_FOR_SECRET
        ///      prompt the user to enter a shared secret. The sender application
        ///      should call otrl_message_initiate_smp, passing NULL as the question.
        ///      When the receiver application resumes the SM protocol by calling
        ///      otrl_message_respond_smp with the secret answer.
        /// - OTRL_SMPEVENT_ASK_FOR_ANSWER
        ///      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
        ///      otrl_message_initiate_smp_q instead)
        /// - OTRL_SMPEVENT_CHEATED
        ///      abort the current auth and update the auth progress dialog
        ///      with progress_percent. otrl_message_abort_smp should be called to
        ///      stop the SM protocol.
        /// - OTRL_SMPEVENT_INPROGRESS 	and
        ///   OTRL_SMPEVENT_SUCCESS 		and
        ///   OTRL_SMPEVENT_FAILURE    	and
        ///   OTRL_SMPEVENT_ABORT
        ///      update the auth progress dialog with progress_percent
        /// - OTRL_SMPEVENT_ERROR
        ///      (same as OTRL_SMPEVENT_CHEATED)
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="smpEvent">An event code for the SMP negotiation</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="progressPercent">The message that was sent</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void HandleSMPEvent(IntPtr opaqueData,
            uint smpEvent,
            IntPtr context,
            ushort progressPercent,
            [MarshalAs(UnmanagedType.LPStr)] string question);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Handle and send the appropriate message(s) to the sender/recipient
        /// depending on the message events. All the events only require an opdata,
        /// the event, and the context. The message and err will be NULL except for
        /// some events (see below). The possible events are:
        /// - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
        ///      Our policy requires encryption but we are trying to send
        ///      an unencrypted message out.
        /// - OTRL_MSGEVENT_ENCRYPTION_ERROR
        ///      An error occured while encrypting a message and the message
        ///      was not sent.
        /// - OTRL_MSGEVENT_CONNECTION_ENDED
        ///      Message has not been sent because our buddy has ended the
        ///      private conversation. We should either close the connection,
        ///      or refresh it.
        /// - OTRL_MSGEVENT_SETUP_ERROR
        ///      A private conversation could not be set up. A gcry_error_t
        ///      will be passed.
        /// - OTRL_MSGEVENT_MSG_REFLECTED
        ///      Received our own OTR messages.
        /// - OTRL_MSGEVENT_MSG_RESENT
        ///      The previous message was resent.
        /// - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
        ///      Received an encrypted message but cannot read
        ///      it because no private connection is established yet.
        /// - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
        ///      Cannot read the received message.
        /// - OTRL_MSGEVENT_RCVDMSG_MALFORMED
        ///      The message received contains malformed data.
        /// - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
        ///      Received a heartbeat.
        /// - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
        ///      Sent a heartbeat.
        /// - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
        ///      Received a general OTR error. The argument 'message' will
        ///      also be passed and it will contain the OTR error message.
        /// - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
        ///      Received an unencrypted message. The argument 'message' will
        ///      also be passed and it will contain the plaintext message.
        /// - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
        ///      Cannot recognize the type of OTR message received.
        /// - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
        ///      Received and discarded a message intended for another instance.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="messageEvent">An event code for the message</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="message">The message that was sent</param>
        /// <param name="error">libgpg-error value to be decoded by LibGPGError.</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void HandleMessageEvent(IntPtr opaqueData,
            uint messageEvent,
            IntPtr context,
            [MarshalAs(UnmanagedType.LPStr)] string message,
            uint error);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Called immediately before a data message is encrypted, and after a data
        /// message is decrypted. The convertType parameter has the value
        /// Sending or Receiving to differentiate these
        /// cases and should be cast to a ConvertType.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="convertType">The convert type is marshalled with LibOTR.ConvertType and is "Sending" for messages that are encrypted and sent, and "Receiving" for messages that are received and decrypted.</param>
        /// <param name="dest">A pointer to the memory allocated to store the conversion</param>
        /// <param name="src">A pointer to the original message</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ConvertMessage(IntPtr opaqueData,
            IntPtr context,
            uint convertType,
            out IntPtr dest,
            IntPtr src);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Deallocate a string returned by ConvertMessage.
        /// </summary>
        /// <param name="opaqueData">Pointer passed back opaquely by libotr</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="dest">A pointer to the memory allocated to store the conversion</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void FreeConvertedMessage(IntPtr opaqueData,
            IntPtr context,
            IntPtr dest);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// When timer_control is called, turn off any existing periodic
        /// timer.
        /// 
        /// Additionally, if interval > 0, set a new periodic timer
        /// to go off every interval seconds.  When that timer fires, you
        /// must call otrl_message_poll(userstate, uiops, uiopdata); from the
        /// main libotr thread.
        /// 
        /// The timing does not have to be exact; this timer is used to
        /// provide forward secrecy by cleaning up stale private state that
        /// may otherwise stick around in memory.  Note that the
        /// timer_control callback may be invoked from otrl_message_poll
        /// itself, possibly to indicate that interval == 0 (that is, that
        /// there's no more periodic work to be done at this time).
        /// 
        /// If you set this callback to NULL, then you must ensure that your
        /// application calls otrl_message_poll(userstate, uiops, uiopdata);
        /// from the main libotr thread every definterval seconds (where
        /// definterval can be obtained by calling
        /// definterval = otrl_message_poll_get_default_interval(userstate);
        /// right after creating the userstate).  The advantage of
        /// implementing the timer_control callback is that the timer can be
        /// turned on by libotr only when it's needed.
        /// 
        /// It is not a problem (except for a minor performance hit) to call
        /// otrl_message_poll more often than requested, whether
        /// timer_control is implemented or not.
        /// 
        /// If you fail to implement the timer_control callback, and also
        /// fail to periodically call otrl_message_poll, then you open your
        /// users to a possible forward secrecy violation: an attacker that
        /// compromises the user's computer may be able to decrypt a handful
        /// of long-past messages (the first messages of an OTR
        /// conversation).
        /// </summary>
        /// <param name="opaqueData">Opaquely-returned value</param>
        /// <param name="interval">Periodic timer</param>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TimerControl(IntPtr opaqueData,
            uint interval);

        /// <summary>
        /// A struct that contains a representation of OtrlMessageAppOps found in libotr-4.1.1/src/message.h
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MessageOps
        {
            [MarshalAs(UnmanagedType.FunctionPtr)] public Policy Policy;
            [MarshalAs(UnmanagedType.FunctionPtr)] public CreatePrivateKey CreatePrivateKey;
            [MarshalAs(UnmanagedType.FunctionPtr)] public LoggedIn LoggedIn;
            [MarshalAs(UnmanagedType.FunctionPtr)] public InjectMessage InjectMessage;
            [MarshalAs(UnmanagedType.FunctionPtr)] public UpdateContextList UpdateContextList;
            [MarshalAs(UnmanagedType.FunctionPtr)] public NewFingerprint NewFingerprint;
            [MarshalAs(UnmanagedType.FunctionPtr)] public WriteFingerprints WriteFingerprints;
            [MarshalAs(UnmanagedType.FunctionPtr)] public GoneSecure GoneSecure;
            [MarshalAs(UnmanagedType.FunctionPtr)] public GoneInsecure GoneInsecure;
            [MarshalAs(UnmanagedType.FunctionPtr)] public StillSecure StillSecure;
            [MarshalAs(UnmanagedType.FunctionPtr)] public MaxMessageSize MaxMessageSize;
            [MarshalAs(UnmanagedType.FunctionPtr)] public AccountName AccountName;
            [MarshalAs(UnmanagedType.FunctionPtr)] public FreeAccountName FreeAccountName;
            [MarshalAs(UnmanagedType.FunctionPtr)] public ReceivedSymmetricKey ReceivedSymmetricKey;
            [MarshalAs(UnmanagedType.FunctionPtr)] public ErrorMessage ErrorMessage;
            [MarshalAs(UnmanagedType.FunctionPtr)] public FreeErrorMessage FreeErrorMessage;
            [MarshalAs(UnmanagedType.FunctionPtr)] public ResentMessagePrefix ResentMessagePrefix;
            [MarshalAs(UnmanagedType.FunctionPtr)] public FreeResentMessagePrefix FreeResentMessagePrefix;
            [MarshalAs(UnmanagedType.FunctionPtr)] public HandleMessageEvent HandleMessageEvent;
            [MarshalAs(UnmanagedType.FunctionPtr)] public HandleSMPEvent HandleSMPEvent;
            [MarshalAs(UnmanagedType.FunctionPtr)] public ConvertMessage ConvertMessage;
            [MarshalAs(UnmanagedType.FunctionPtr)] public FreeConvertedMessage FreeConvertedMessage;
            [MarshalAs(UnmanagedType.FunctionPtr)] public TimerControl TimerControl;
        }

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Handle a message about to be sent to the network.  It is safe to pass
        /// all messages about to be sent to this routine. callback is a
        /// function that will be called in the event that a new ConnContext is
        /// created.  It will be passed the data that you supplied, as well as a
        /// pointer to the new ConnContext.  You can use this to add
        /// application-specific information to the ConnContext using the
        /// "context->app" field, for example.  If you don't need to do this, you
        /// can pass NULL for the last two arguments of SendMessage.
        /// 
        /// tlvs is a chain of TLVs to append to the private message.  It is
        /// usually correct to just pass NULL here.
        /// 
        /// If non-NULL, MessageOps.ConvertMessage will be called just before encrypting a
        /// message.
        /// 
        /// "remoteInstanceTag" specifies the instance tag of the buddy
        /// (protocol version 3 only). Meta-instances may also be specified
        /// (e.g., OTRL_INSTAG_MOST_SECURE). If "context" is not NULL, it will be set to
        /// the ConnContext used for sending the message.
        /// 
        /// If no fragmentation or msg injection is wanted, use SendSkip as the
        /// OtrlFragmentPolicy. In this case, this function will assign messages
        /// with the encrypted msg. If the routine returns non-zero, then the library
        /// tried to encrypt the message, but for some reason failed. DO NOT send the
        /// message in the clear in that case. If *messagep gets set by the call to
        /// something non-NULL, then you should replace your message with the contents
        /// of *messagep, and send that instead.
        /// 
        /// Other fragmentation policies are SendAll, SendAllButLast, or SendAllButFirst.
        /// In these cases, the appropriate fragments will be automatically sent. For the
        /// last two policies, the remaining fragment will be passed in message.
        /// 
        /// Call FreeMessage(*messagep) if you don't need *messagep or when you're
        /// done with it.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="messageOps">Pointer to a marshalled instance of the MessageOps struct</param>
        /// <param name="opaqueData">Opaquely-returned value</param>
        /// <param name="accountName">Account name used internally to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        /// <param name="recipient">Recipient used to identify a user that isn't you using OTR</param>
        /// <param name="remoteInstanceTag">Instance tag of the remote user</param>
        /// <param name="message">LPSTR to the message to send</param>
        /// <param name="tlvs">Pointer to a machine-readable data array known as a "TLV" which is encrypted</param>
        /// <param name="newMessage">Pointer to the message to send</param>
        /// <param name="fragmentPolicy">LPSTR to the message to send</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="callback">Delegate to return with application data and a new `ConnContext` created by libotr</param>
        /// <param name="callbackData">Application data passed in earlier and returned by libotr</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError.</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_message_sending", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint SendMessage(IntPtr userState,
            IntPtr messageOps,
            IntPtr opaqueData,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol,
            [MarshalAs(UnmanagedType.LPStr)] string recipient,
            uint remoteInstanceTag,
            ref IntPtr message,
            IntPtr tlvs,
            IntPtr newMessage,
            uint fragmentPolicy,
            ref IntPtr context,
            ConnContextCallback callback,
            IntPtr callbackData);

        /// <summary>
        /// libotr-4.1.1/src/message.h:
        /// 
        /// Handle a message just received from the network.  It is safe to pass
        /// all received messages to this routine.  add_appdata is a function
        /// that will be called in the event that a new ConnContext is created.
        /// It will be passed the data that you supplied, as well as
        /// a pointer to the new ConnContext.  You can use this to add
        /// application-specific information to the ConnContext using the
        /// "context->app" field, for example.  If you don't need to do this, you
        /// can pass NULL for the last two arguments of otrl_message_receiving.
        /// 
        /// If non-NULL, ops->convert_msg will be called after a data message is
        /// decrypted.
        /// 
        /// If "contextp" is not NULL, it will be set to the ConnContext used for
        /// receiving the message.
        /// 
        /// If otrl_message_receiving returns 1, then the message you received
        /// was an internal protocol message, and no message should be delivered
        /// to the user.
        /// 
        /// If it returns 0, then check if *messagep was set to non-NULL.  If
        /// so, replace the received message with the contents of *messagep, and
        /// deliver that to the user instead.  You must call
        /// ReceiveMessage(message) when you're done with it.  If tlvsp is
        /// non-NULL, *tlvsp will be set to a chain of any TLVs that were
        /// transmitted along with this message.  You must call
        /// otrl_tlv_free(*tlvsp) when you're done with those.
        /// 
        /// If otrl_message_receiving returns 0 and *messagep is NULL, then this
        /// was an ordinary, non-OTR message, which should just be delivered to
        /// the user without modification.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="messageOps">Pointer to a marshalled instance of the MessageOps struct</param>
        /// <param name="opaqueData">Opaquely-returned value</param>
        /// <param name="accountName">Account name used internally to identify your account using OTR</param>
        /// <param name="protocol">Protocol used to identify your account using OTR</param>
        /// <param name="sender">Sender used to identify a user that isn't you using OTR</param>
        /// <param name="message">LPSTR to the message the application received</param>
        /// <param name="newMessage">LPTSTR to the decrypted message</param>
        /// <param name="tlvs">Pointer to a machine-redable data array known as a "TLV" which is encrypted</param>
        /// <param name="context">Pointer to a `ConnContext` used by libotr</param>
        /// <param name="callback">Delegate to return with application data and a new `ConnContext` created by libotr</param>
        /// <param name="callbackData">Application data passed in earlier and returned by libotr</param>
        /// <returns>If it returns 1, the message was an internal protocol message, so it should not be delivered to the application. If it returns 0, the newMessage was set correctly.</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_message_receiving", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ReceiveMessage(IntPtr userState,
            IntPtr messageOps,
            IntPtr opaqueData,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol,
            [MarshalAs(UnmanagedType.LPStr)] string sender,
            [MarshalAs(UnmanagedType.LPStr)] string message,
            ref IntPtr newMessage,
            out IntPtr tlvs,
            ref IntPtr context,
            ConnContextCallback callback,
            IntPtr callbackData);

        /// <summary>
        /// Deallocate a message allocated by other *Message routines.
        /// </summary>
        /// <param name="message">The LPTSTR message pointer</param>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_message_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeMessage(IntPtr message);

        /// <summary>
        /// Generate a private DSA key for a given account, storing it into a
        /// file on disk, and loading it into the given OtrlUserState.  Overwrite any
        /// previously generated keys for that account in that OtrlUserState.
        /// </summary>
        /// <param name="userState">Pointer to the user state created by CreateUserState() to be marshalled to LibOTR.UserState</param>
        /// <param name="file">Path to the file to store the generated key.</param>
        /// <param name="accountName">Account name used internally to identify your account using OTR.</param>
        /// <param name="protocol">Protocol used to identify your account using OTR.</param>
        /// <returns>Returns a libgpg-error value to be decoded by LibGPGError.</returns>
        [DllImport("libotr.so", CharSet = CharSet.Auto, EntryPoint = "otrl_privkey_generate", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint GenerateKey(IntPtr userState,
            [MarshalAs(UnmanagedType.LPStr)] string file,
            [MarshalAs(UnmanagedType.LPStr)] string accountName,
            [MarshalAs(UnmanagedType.LPStr)] string protocol);
    }
}