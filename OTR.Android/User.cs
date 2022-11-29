using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using OTR.Android.Interop;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace OTR.Android
{
    public class User
    {
        private static Dictionary<State, User> _userStates;

        static User()
        {
            User._userStates = new Dictionary<State, User>();
        }

        public static User FromUnmanaged(IntPtr ptrUserState)
        {
            foreach (State state in User._userStates.Keys)
            {
                if (state.Unmanaged() == ptrUserState)
                {
                    return _userStates[state];
                }
            }

            return null;
        }

        private State _state;
        private LibOTR.MessageOps _ops;

        /// <summary>
        /// A wrapper for the LibOTR.UserState struct and code relating to its internal memory management. 
        /// </summary>
        public class State
        {
            private IntPtr _handle;
            private User _user;

            /// <summary>
            /// Initialise a new UserState from LibOTR
            /// </summary>
            public State(User user)
            {
                this._handle = LibOTR.CreateUserState();
                this._user = user;
            }

            /// <summary>
            /// Return the unmanaged pointer to libotr's UserState.
            /// </summary>
            /// <returns>Unmanaged pointer to libotr's UserState</returns>
            public IntPtr Unmanaged()
            {
                return _handle;
            }

            /// <summary>
            /// Store a managed copy of libotr's UserState.
            /// </summary>
            /// <returns>Managed LibOTR.UserState</returns>
            /// <exception cref="NotImplementedException">Thrown when the UserState has already been marshalled and is in memory</exception>
            public WeakReference Marshal()
            {
                return new WeakReference((LibOTR.UserState)System.Runtime.InteropServices.Marshal.PtrToStructure(_handle, typeof(LibOTR.UserState)));
            }

            /// <summary>
            /// Free the unmanaged UserState through the LibOTR library, and additionally, call FreeManaged to clean up that instance.
            /// </summary>
            private void FreeUnmanaged()
            {
                LibOTR.FreeUserState(_handle);
            }

            /// <summary>
            /// For now, the destructor will just call FreeUnmanaged
            /// </summary>
            ~State()
            {
                FreeUnmanaged();
                User._userStates.Remove(this);
            }
        }

        public User()
        {
            SetupUserState();
        }

        public void SetupUserState()
        {
            _state = new User.State(this);
        }

        public GPGError ReadPrivateKeyFingerprints(string file)
        {
            uint error = LibOTR.ReadPrivateKeyFingerprints(_state.Unmanaged(), file, IntPtr.Zero, IntPtr.Zero);
            return GPGError.Marshal(error);
        }

        public GPGError ReadPrivateKey(string file)
        {
            uint error = LibOTR.ReadPrivateKey(_state.Unmanaged(), file);
            return GPGError.Marshal(error);
        }

        public GPGError ReadInstanceTags(string file)
        {
            uint error = LibOTR.ReadInstanceTags(_state.Unmanaged(), file);
            return GPGError.Marshal(error);
        }

        public GPGError GenerateKey(string file, string accountName, string protocol)
        {
            uint error = LibOTR.GenerateKey(_state.Unmanaged(), file, accountName, protocol);
            return GPGError.Marshal(error);
        }

        ~User()
        {
            _state = null;
        }
    }
}