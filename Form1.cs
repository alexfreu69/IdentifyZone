using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace IdentifyZone2
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            lblResult.Text = "Zone: " + GetZoneName(CheckSecurityZone(textBox1.Text));
        }

        private string GetZoneName(int zone)
        {
            switch (zone)
            {
                case 4:
                    return "Untrusted";
                case 3:
                    return "Internet";
                case 2:
                    return "Trusted";
                case 1:
                    return "Local Intranet";
                case 0:
                    return "My Computer";
                case -1:
                    return "Function error!";
                case -2:
                    return "COMException";
                case -3:
                    return "Unknown Zone!";
                default:
                    return "";
	        }
        }



        private int CheckSecurityZone(string url)
        {
            int _ret = -4;

            try
            {
                IInternetSecurityManager _ism = IISMFactory.GetISM();
                UInt32 _pdwZone = 0;
                int _res = _ism.MapUrlToZone(url, out _pdwZone, 0);
                if (_res == 0)
                {
                    if (_pdwZone < 5)
                        _ret = (int)_pdwZone;
                    else
                        _ret = -3;
                }
                else
                    _ret = -1;
            }
            catch (COMException)
            {
                _ret = -2;
            }

            return _ret;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            string[] x = Environment.GetCommandLineArgs();
            if (x.Length == 3)
            {
                string res = GetZoneName(CheckSecurityZone(x[1]));
                System.IO.File.WriteAllText(x[2], x[1]+ " => " + res); 
                Application.Exit();
            }
        }
    }

    #region IInternetSecurityManager Interface
    [ComVisible(true), ComImport,
    GuidAttribute("79EAC9EE-BAF9-11CE-8C82-00AA004BA90B"),
    InterfaceTypeAttribute(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IInternetSecurityManager
    {
        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int SetSecuritySite(
            [In] IntPtr pSite);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int GetSecuritySite(
            out IntPtr pSite);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int MapUrlToZone(
            [In, MarshalAs(UnmanagedType.LPWStr)] string pwszUrl,
            out UInt32 pdwZone,
            UInt32 dwFlags);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int GetSecurityId(
            [In, MarshalAs(UnmanagedType.LPWStr)] string pwszUrl,
            [Out] IntPtr pbSecurityId, [In, Out] ref UInt32 pcbSecurityId,
            [In] ref UInt32 dwReserved);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int ProcessUrlAction(
            [In, MarshalAs(UnmanagedType.LPWStr)] string pwszUrl,
            UInt32 dwAction,
            IntPtr pPolicy, UInt32 cbPolicy,
            IntPtr pContext, UInt32 cbContext,
            UInt32 dwFlags,
            UInt32 dwReserved);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int QueryCustomPolicy(
            [In, MarshalAs(UnmanagedType.LPWStr)] string pwszUrl,
            ref Guid guidKey,
            out IntPtr ppPolicy, out UInt32 pcbPolicy,
            IntPtr pContext, UInt32 cbContext,
            UInt32 dwReserved);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int SetZoneMapping(
            UInt32 dwZone,
            [In, MarshalAs(UnmanagedType.LPWStr)] string lpszPattern,
            UInt32 dwFlags);

        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int GetZoneMappings(
            [In] UInt32 dwZone, //One or more of tagURLZONE enums
            out IEnumString ppenumString,
            [In] UInt32 dwFlags);
    }
    public static class IISMFactory
    {
        public static Guid CLSID_InternetSecurityManager = new Guid("7b8a2d94-0ac9-11d1-896c-00c04fb6bfc4");
        public static Guid IID_IInternetSecurityManager = new Guid("79eac9ee-baf9-11ce-8c82-00aa004ba90b");

        public static IInternetSecurityManager GetISM()
        {
            Type t = Type.GetTypeFromCLSID(CLSID_InternetSecurityManager);
            object securityManager = Activator.CreateInstance(t);
            IInternetSecurityManager ism = (IInternetSecurityManager)securityManager;
            return ism;
        }
    }

    #endregion

}
