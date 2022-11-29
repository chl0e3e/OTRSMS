using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace OTR.Android
{
    public class Context
    {
        private static Dictionary<IntPtr, Context> _contexts;

        static Context()
        {
            Context._contexts = new Dictionary<IntPtr, Context>();
        }

        public static Context FromPtr(IntPtr handle)
        {
            if (!_contexts.ContainsKey(handle))
            {
                _contexts.Add(handle, new Context(handle));
            }

            return _contexts[handle];
        }

        private IntPtr _handle;

        public Context(IntPtr handle)
        {
            this._handle = handle;
        }
    }
}