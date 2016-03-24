using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using Microsoft.UpdateServices.Administration;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;
using System.Net.Security;
using System.Security;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using WindowsInstaller;
using Newtonsoft.Json;
using CERTENROLLLib;
//using WixSharp;

namespace CarteiroWin
{
    /// <commands>
    /// Set-DNSName name - Sets the current configured dnsname of the server in the registry, this is important for the SSL Connection
    /// Get-DNSName - Returns the dnsname of the server
    /// Test-SSL - Returns True if the Connection to the wsus is SSL secure
    /// Set-Cert CertPath CertPassword - Sets the given WSUS Certificate in the WSUS Configuration
    /// Get-Package DownloadURI Name [Description] - Downloads a package into the cache
    /// </commands>
    class RemoteHook
    {
        private string REG_PATH = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\bitformerGmbH\\CarteiroWin";

        private static IUpdateServer ConnectLocal()
        {
            string dnsName = (string)Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\bitformerGmbH\\CarteiroWin",
                              "DnsServerName",
                              Environment.MachineName);
            try
            {
                IUpdateServer wsus = AdminProxy.GetUpdateServer(dnsName, true, 8531);
                return wsus;
            }
            catch (Exception)
            {
                Console.Error.WriteLine("Try to unsafe connect to " + Environment.MachineName);
                IUpdateServer wsus = AdminProxy.GetUpdateServer(Environment.MachineName, false, 8530);
                Console.Error.WriteLine("WARNING: SSL Connection could not been established, connection is unsafe");
                return wsus;
            }
        }

        private void SetDnsName(string name)
        {
            Registry.SetValue(REG_PATH, "DnsServerName", name);
        }

        private string GetDnsName()
        {
            string name = (string)Registry.GetValue(REG_PATH, "DnsServerName", "Not found");
            return name;
        }

        private static X509Certificate2 DownloadSslCertificate(string strDNSEntry)
        {
            using (TcpClient client = new TcpClient())
            {
                client.Connect(strDNSEntry, 8531);
                SslStream ssl = new SslStream(client.GetStream(), false, ValidateServerCertificate, null);
                try
                {
                    ssl.AuthenticateAsClient(strDNSEntry);
                }
                catch (AuthenticationException e)
                {
                    Console.Error.WriteLine(e.Message);
                    ssl.Close();
                    client.Close();
                    return null;
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e.Message);
                    ssl.Close();
                    client.Close();
                    return null;
                }
                var cert = new X509Certificate2(ssl.RemoteCertificate);
                ssl.Close();
                client.Close();
                return cert;
            }
        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            Console.Error.WriteLine("Certificate error: {0}", sslPolicyErrors);
            return true;
        }

        private static void SetWsusCertificate(IUpdateServer wServ)
        {
            //Self Signed Certifications creation by WSUS server is deprecated, need an workaround
            if (wServ.IsConnectionSecureForApiRemoting)
            {
                try
                {
                    String secret = "Secure!";
                    X509Certificate2 cert = CreateSelfSignedCertificate("Carteiro");
                    File.WriteAllBytes("C:\\carteiro.pfx", cert.Export(X509ContentType.Pfx, secret));
                    File.WriteAllBytes("C:\\carteiro.cer", cert.Export(X509ContentType.Cert));
                    SetWsusCertificate("C:\\carteiro.pfx", secret, wServ);

                    //Importing into other stores
                    System.Security.Cryptography.X509Certificates.X509Store authRootStore = new System.Security.Cryptography.X509Certificates.X509Store("AuthRoot", System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                    System.Security.Cryptography.X509Certificates.X509Store trustedPublisherStore = new System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);

                    authRootStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
                    trustedPublisherStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);

                    authRootStore.Add(cert);
                    trustedPublisherStore.Add(cert);

                    authRootStore.Close();
                    trustedPublisherStore.Close();

                    Console.WriteLine("INFO: certificates were succesfully imported into AuthRoot and Trusted Publisher stores");
                    Console.WriteLine("INFO: setting new WSUS Certificate finished!");
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("ERROR: " + e.Message);
                }
            }
            else
            {
                Console.Error.WriteLine("ERROR: this operation is not possible with an unsafe connection");
            }
        }

        private static void SetWsusCertificate(string certPath, string certPass, IUpdateServer wServ)
        {
            if (wServ.IsConnectionSecureForApiRemoting)
            {
                try
                {
                    var wsusConf = wServ.GetConfiguration();
                    wsusConf.SetSigningCertificate(certPath, certPass);
                    wsusConf.Save();
                    Console.WriteLine("INFO: new Certificate imported");
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("ERROR: " + e.Message);
                }
            }
            else
            {
                Console.Error.WriteLine("ERROR: this operation is not possible with an unsafe connection");
            }
        }

        //Source https://wsuspackagepublisher.codeplex.com/SourceControl/latest
        internal static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid = new CObjectId();
            oid.InitializeFromValue("1.3.6.1.5.5.7.3.3"); // Signature du code.
            var oidlist = new CObjectIds();
            oidlist.Add(oid);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            DateTime today = DateTime.Now.ToUniversalTime();
            cert.NotBefore = today;
            // this cert is valid for 5 years
            cert.NotAfter = today.AddYears(5);
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = subjectName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            );
        }

        private void ReturnPayload(Dictionary<string, string> dataDict)
        {
            List<Dictionary<string, string>> retList = new List<Dictionary<string, string>>();
            retList.Add(dataDict);
            ReturnPayload(retList);
        }

        private void ReturnPayload(List<Dictionary<string, string>> dataList)
        {
            string outputString = string.Empty;
            if (dataList != null)
            {
                outputString = "PAYLOAD START-" + JsonConvert.SerializeObject(dataList) + "-PAYLOAD END";
                //Path formatting for console output
                outputString = outputString.Replace("\\","/");
            }
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine(Console.Out.Encoding.CodePage);
            Console.Out.WriteLine(outputString);
        }

        public static string FromDictionaryToJson(Dictionary<string, string> dictionary)
        {
            var kvs = dictionary.Select(kvp => string.Format("\"{0}\":\"{1}\"", kvp.Key, string.Join(",", kvp.Value)));
            return string.Concat("{", string.Join(",", kvs), "}");
        }

        public string GetCachePath()
        {
            return (string)Registry.GetValue(REG_PATH, "Path", null) + "cache\\";
        }

        //Package-Management
        private Dictionary<string, string> DownloadPackage(string path, string name)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            string cachePath = GetCachePath();
            string msiFilePath = cachePath + name;
            string PackageVersion = string.Empty;

            // Delete old Cache
            if(System.IO.Directory.Exists(cachePath))
                System.IO.Directory.Delete(cachePath, true);
            // Create new Cache Folder
            if (!Directory.Exists(cachePath))
                Directory.CreateDirectory(cachePath);

            // Look if the given Path is an URL
            if (Uri.IsWellFormedUriString(path, UriKind.RelativeOrAbsolute))
            {
                WebClient client = new WebClient();
                try
                {
                    client.DownloadFile(path, msiFilePath);
                }
                catch (WebException e)
                {
                    Console.Error.WriteLine(e);
                }
            }
            //Path is a local path
            else
            {
                if (System.IO.File.Exists(path))
                {
                    System.IO.File.Copy(path, msiFilePath);
                }
                else
                {
                    msiFilePath = null;
                    Console.Error.WriteLine("FileNotFound: " + path);
                }
            }

            if(msiFilePath != null)
            {
                PackageVersion = (GetMsiProperty(msiFilePath, "ProductVersion"));
                dict.Add("PackageVersion", PackageVersion);
                dict.Add("ProductName", GetMsiProperty(msiFilePath, "ProductName"));
                dict.Add("Manufacturer", GetMsiProperty(msiFilePath, "Manufacturer"));
                dict.Add("MsiFileName", name + "_" + dict["PackageVersion"] + ".msi");
                dict.Add("Value", "FileFound");

                // Check if Version already exists and Rename the downloaded File
                if (!System.IO.File.Exists(msiFilePath + "_" + dict["PackageVersion"] + ".msi"))
                {
                    System.IO.File.Copy(msiFilePath, msiFilePath + "_" + dict["PackageVersion"] + ".msi");
                    dict.Add("AlreadyDownloaded", "False");
                }
                else
                    dict.Add("AlreadyDownloaded", "True");

                // Cleanup downloaded File
                System.IO.File.Delete(msiFilePath);
            }
            
            return dict;
        }
        private IUpdate ImportPackage(IUpdateServer wsus, string packagepath, string title, string desc, string vendor)
        {
            //Be sure that the baseapplicabilityrules.xsd exists
            var schemaPathx86 = Path.Combine("C:\\Program Files (x86)", "Update Services\\Schema");
            var schemaPathx64 = Path.Combine("C:\\Program Files", "Update Services\\Schema");
            var updateservicesPathx86 = Path.Combine("C:\\Program Files (x86)", "Update Services");
            
            if (!File.Exists(schemaPathx86 + "baseapplicabilityrules.xsd"))
            {
                Console.WriteLine("INFO: Need to copy Update Services schemata into x86 Folder");
                Console.WriteLine("DEBUG: " + schemaPathx86);
                Console.WriteLine("DEBUG: " + schemaPathx64);
                Console.WriteLine("DEBUG: " + updateservicesPathx86);

                if (!Directory.Exists(updateservicesPathx86))
                {
                    Directory.CreateDirectory(updateservicesPathx86);
                    Console.WriteLine("INFO: Created Folder " + updateservicesPathx86);
                }
                if (!Directory.Exists(schemaPathx86))
                {
                    Directory.CreateDirectory(schemaPathx86);
                    Console.WriteLine("INFO: Created Folder " + schemaPathx86);

                    foreach (var file in Directory.GetFiles(schemaPathx64))
                    {
                        File.Copy(file, Path.Combine(schemaPathx64, Path.GetFileName(file)));
                        Console.WriteLine("INFO: Copy File " + file);
                    }
                }
            }

            Console.WriteLine("Installing Package...");
            SoftwareDistributionPackage sdp = new SoftwareDistributionPackage();
            sdp.PopulatePackageFromWindowsInstaller(packagepath);
            sdp.Title = title;
            sdp.Description = desc;
            sdp.VendorName = vendor;

            //Look for Windows Vista
            sdp.IsInstallable = "<bar:WindowsVersion Comparison='GreaterThanOrEqualTo' MajorVersion='6' MinorVersion='0' />";

            string sdpFilePath = Environment.GetEnvironmentVariable("TEMP") + "\\" + sdp.Title + sdp.PackageId.ToString() + ".txt";

            sdp.Save(sdpFilePath);
            IPublisher publisher = wsus.GetPublisher(sdpFilePath);
            FileInfo dir = new FileInfo(packagepath);
            publisher.PublishPackage(dir.Directory.ToString(), null);

            Console.WriteLine("CAB generated");
            IUpdate publishedUpdate = wsus.GetUpdate(new UpdateRevisionId(sdp.PackageId));
            return publishedUpdate;
        }
        private string GetMsiProperty(string msiFile, string Property)
        {
            string retVal = string.Empty;

            Type classType = Type.GetTypeFromProgID("WindowsInstaller.Installer");
            Object installerObj = Activator.CreateInstance(classType);
            Installer installer = installerObj as Installer;

            // Open the msi file for reading
            // 0 - Read, 1 - Read/Write
            Database database = installer.OpenDatabase(msiFile, 0);
            // Fetch the requested property
            string sql = String.Format("SELECT Value FROM Property WHERE Property='{0}'", Property);
            View view = database.OpenView(sql);
            view.Execute(null);

            // Read in the fetched record
            Record record = view.Fetch();
            if (record != null)
                retVal = record.get_StringData(1);
            view.Close();
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(view);
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(database);
            view = null;
            database = null;
            return retVal;
        }

        private List<Dictionary<string,string>> GetUpdates(IUpdateServer wsus, string name = "")
        {
            List<Dictionary<string, string>> retList = new List<Dictionary<string, string>>();
            UpdateCollection updates = new UpdateCollection();
            if (name == "")
            {
                updates = wsus.GetUpdates();
            }
            else
            {
                updates = wsus.SearchUpdates(name);
            }
            foreach (IUpdate update in updates)
            {
                if (update.Description == "Carteiro Update Package")
                {
                    Dictionary<string,string> details = new Dictionary<string, string>();
                    details.Add("Id", update.Id.UpdateId.ToString());
                    details.Add("Title", update.Title);
                    details.Add("Description", update.Description.Trim());
                    details.Add("CreationDate", update.CreationDate.ToString());
                    details.Add("IsApproved", update.IsApproved.ToString());
                    details.Add("IsDeclined", update.IsDeclined.ToString());
                    retList.Add(details);
                }
            }
            return retList;
        }

        private Dictionary<string,string> DeleteUpdate(IUpdateServer wsus, string id)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            try
            {
                IUpdate deletedUpdate = wsus.GetUpdate(new UpdateRevisionId(new Guid(id)));
                if (deletedUpdate.IsApproved)
                    deletedUpdate.Decline();
                wsus.DeleteUpdate(new Guid(id));
                dict.Add("Title", deletedUpdate.Title);
                dict.Add("Id", deletedUpdate.Id.UpdateId.ToString());
                dict.Add("Status", "Deleted");
            }
            catch (WsusObjectNotFoundException)
            {
                dict.Add("Id", id);
                dict.Add("Status", "Not Found");
            }
            
            return dict;
        }

        //private void CreateUpdateMsi()
        //{
        //    Project project =
        //     new Project("Foobar",

        //         new PathFileAction(
        //                     @"%WindowsFolder%\notepad.exe",
        //                     "readme.txt",
        //                     "INSTALLDIR",
        //                     Return.asyncNoWait,
        //                     When.After,
        //                     Step.InstallFinalize,
        //                     new Condition("(NOT Installed) AND (UILevel > 3)")) //execute this action during the installation but only if it is not silent mode (UILevel > 3)
        //     );

        //    project.GUID = new Guid("6f330b47-2577-43ad-9095-1861ba25889b");
        //    project.SourceBaseDir = Environment.CurrentDirectory;
        //    project.OutFileName = "setup";

        //    Compiler.WixLocation = ((string)Registry.GetValue(REG_PATH, "Path", null) + "CarteiroWin\\bin\\");
        //    Compiler.BuildMsi(project);
        //}

        //WSUS Group-Management
        private List<Dictionary<string, string>> GetComputerTargetGroups(IUpdateServer wsus)
        {
            List<Dictionary<string, string>> retList = new List<Dictionary<string, string>>();
            ComputerTargetGroupCollection groups = new ComputerTargetGroupCollection();
            groups = wsus.GetComputerTargetGroups();
            foreach (IComputerTargetGroup group in groups)
            {
                Dictionary<string,string>  details = new Dictionary<string, string>();
                details.Add("Id", group.Id.ToString());
                details.Add("Name", group.Name);
                retList.Add(details);
            }
            return retList;
        }

        private List<Dictionary<string, string>> GetComputerTargetGroup(IUpdateServer wsus, string id)
        {
            List<Dictionary<string, string>> retList = new List<Dictionary<string, string>>();
            IComputerTargetGroup group = wsus.GetComputerTargetGroup(new Guid(id));
            ComputerTargetCollection members = group.GetComputerTargets();
            foreach (IComputerTarget member in members)
            {
                Dictionary<string,string> details = new Dictionary<string, string>();
                details.Add("Id", member.Id);
                details.Add("Name", member.FullDomainName);
                details.Add("Ip", member.IPAddress.ToString());
                details.Add("LastReport", member.LastReportedInventoryTime.ToString());
                details.Add("ComputerRole", member.ComputerRole.ToString());
                
                retList.Add(details);
            }
            return retList;
        }

        private Dictionary<string, string> GetComputerTargetStatus(IUpdateServer wsus, string id)
        {


            Dictionary<string, string> retDict = new Dictionary<string, string>();
            IComputerTarget target = wsus.GetComputerTarget(id);
            IUpdateSummary summary = target.GetUpdateInstallationSummary();

            retDict.Add("InstalledCount", summary.InstalledCount.ToString());
            retDict.Add("DownloadedCount", summary.DownloadedCount.ToString());
            retDict.Add("FailedCount", summary.FailedCount.ToString());
            retDict.Add("InstalledPendingRebootCount", summary.InstalledPendingRebootCount.ToString());
            retDict.Add("IsSummedAcrossAllUpdates", summary.IsSummedAcrossAllUpdates.ToString());
            retDict.Add("LastUpdated", summary.LastUpdated.ToString());
            retDict.Add("NotApplicableCount", summary.NotApplicableCount.ToString());
            retDict.Add("UnknownCount", summary.UnknownCount.ToString());
            retDict.Add("NotInstalledCount", summary.NotInstalledCount.ToString());
            return retDict;
        }

        static void Main(string[] args)
        {
            var hook = new RemoteHook();
            IUpdateServer wsusServer = ConnectLocal();
            var dict = new Dictionary<string, string>();
            if (args.Length > 0)
            {
                X509Certificate2 cert = DownloadSslCertificate(Environment.MachineName);
                switch (args[0])
                {
                    case "Set-DNSName":
                        try
                        {
                            var name = args[1];
                            hook.SetDnsName(name);
                            dict["value"] = "true";
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.WriteLine("ERROR: missing arguments");
                        }
                        break;
                    case "Get-DNSName":
                        dict.Add("value", hook.GetDnsName());
                        hook.ReturnPayload(dict);
                        break;
                    case "Test-SSL":
                        dict.Add("value", wsusServer.IsConnectionSecureForApiRemoting.ToString());
                        hook.ReturnPayload(dict);
                        break;
                    case "Set-Cert":
                        try
                        {
                            var path = args[1];
                            var pass = args[2];
                            SetWsusCertificate(path, pass, wsusServer);
                            dict["value"] = "true";
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.Error.WriteLine("No Arguments found, generating new Certificate");

                            SetWsusCertificate(wsusServer);
                        }
                        break;
                    case "Get-Cache":
                        var cachePath = hook.GetCachePath();
                        List<Dictionary<string, string>> dataList = new List<Dictionary<string, string>>();
                        if (System.IO.Directory.Exists(cachePath))
                        {
                            foreach (var file in System.IO.Directory.GetFiles(cachePath))
                            {
                                Dictionary<string, string> entry = new Dictionary<string, string>();
                                entry.Add("MsiFileName", hook.GetMsiProperty(file, "ProductName"));
                                entry.Add("PackageVersion", hook.GetMsiProperty(file, "ProductVersion"));
                                dataList.Add(entry);
                            }
                            hook.ReturnPayload(dataList);
                        }
                        break;
                    case "Test-Cert":
                        if (cert != null)
                        {
                            if (cert.IssuerName.Name == hook.GetDnsName())
                            {
                                dict["value"] = "true";
                            }
                            else
                            {
                                dict["value"] = "false";
                            }
                        }
                        else
                            Console.WriteLine("ERROR: No Certificate found");
                        break;
                    case "Import-Package":
                        try
                        {
                            var path = hook.GetCachePath() + args[1];
                            try
                            {
                                string desc = "Carteiro Update Package";
                                Console.WriteLine(path);
                                string name = hook.GetMsiProperty(path, "ProductName");
                                string manufacturer = hook.GetMsiProperty(path, "Manufacturer");
                                string version = hook.GetMsiProperty(path, "ProductVersion");
                                IUpdate update = hook.ImportPackage(wsusServer, path, name, desc, manufacturer);
                                dict.Add("Title", update.Title);
                                dict.Add("Id", update.Id.UpdateId.ToString());
                                dict.Add("Manufacturer", manufacturer);
                                dict.Add("Version", version);
                                dict.Add("Status", "Imported");
                                dict.Add("CreationDate", update.CreationDate.ToString());
                                Console.WriteLine(dict.ToString());
                            }
                            catch (Exception e)
                            {
                                dict.Add("Status", "Not Imported");
                                Console.Error.WriteLine(e);
                            }
                            hook.ReturnPayload(dict);
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.Error.WriteLine("ERROR: missing argument(s)");
                        }
                        break;

                    case "Get-Package":
                        try
                        {
                            var path = args[1];
                            var name = args[2];
                            dict = hook.DownloadPackage(path, name);
                            Console.WriteLine(dict["MsiFileName"]);
                            dict.Add("Status", "Downloaded");
                            hook.ReturnPayload(dict);
                        }
                        catch (Exception e)
                        {
                            dict.Add("Value", "FileNotFound");
                            Console.Error.WriteLine(e);
                            hook.ReturnPayload(dict);
                        }
                        break;

                    case "Get-Updates":
                        List<Dictionary<string, string>> resUpdates = new List<Dictionary<string, string>>();
                        resUpdates = args.Length > 1 ? hook.GetUpdates(wsusServer, args[1]) : hook.GetUpdates(wsusServer);
                        hook.ReturnPayload(resUpdates);
                        break;

                    case "Delete-Update":
                        try
                        {
                            var id = args[1];
                            dict = hook.DeleteUpdate(wsusServer, id);
                            hook.ReturnPayload(dict);
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.Error.WriteLine("ERROR: missing argument(s)");
                        }
                        catch (Exception e)
                        {
                            Console.Error.WriteLine(e);
                        }
                        break;

                    //TODO Not Implemented Yet
                    case "Approve-Update":
                        try
                        {
                            var update_id = args[1];
                            var option = args[2];
                            var group_id = args[3];
                            Dictionary<string, string> resVal = new Dictionary<string, string>();
                            IUpdate update = wsusServer.GetUpdate(new UpdateRevisionId(new Guid(update_id)));
                            IComputerTargetGroup group = wsusServer.GetComputerTargetGroup(new Guid(group_id));
                            switch (option)
                            {
                                case "Install":
                                    update.Approve(UpdateApprovalAction.Install, group);
                                    resVal.Add("Value", "installed");
                                    break;
                                case "Uninstall":
                                    if (update.UninstallationBehavior.IsSupported)
                                    {
                                        update.Approve(UpdateApprovalAction.Uninstall, group);
                                        resVal.Add("Value", "uninstalled");
                                    }
                                    else
                                        resVal.Add("Value", "not supported");
                                    break;
                                case "NotApproved":
                                    try
                                    {
                                        update.Approve(UpdateApprovalAction.NotApproved, group);
                                    }
                                    catch (InvalidOperationException)
                                    {
                                        Console.Error.WriteLine("Cannot deapprove for all computers, instead declining it");
                                        update.Decline();
                                        resVal.Add("Value", "declined");
                                    }
                                    resVal.Add("Value", "notApproved");
                                    break;
                            }
                            update.RefreshUpdateApprovals();
                            hook.ReturnPayload(resVal);
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.Error.WriteLine("ERROR: missing argument(s)");
                        }
                        break;

                    case "Get-Groups":
                        List<Dictionary<string, string>> resGroups = new List<Dictionary<string, string>>();
                        resGroups = hook.GetComputerTargetGroups(wsusServer);
                        hook.ReturnPayload(resGroups);
                        break;

                    case "Get-Group":
                        try
                        {
                            var id = args[1];
                            List<Dictionary<string, string>> resList = new List<Dictionary<string, string>>();
                            resList = hook.GetComputerTargetGroup(wsusServer, id);
                            hook.ReturnPayload(resList);
                        }
                        catch (IndexOutOfRangeException)
                        {
                            Console.Error.WriteLine("ERROR: missing argument(s)");
                        }
                        break;

                    case "Get-Client-Status":
                        try
                        {
                            var id = args[1];
                            List<Dictionary<string,string>> resList = new List<Dictionary<string, string>>();
                            Dictionary<string, string> retDict = new Dictionary<string, string>();
                            retDict = hook.GetComputerTargetStatus(wsusServer, id);
                            resList.Add(retDict);
                            hook.ReturnPayload(resList);
                        }
                        catch (Exception)
                        {
                            Console.Error.WriteLine("ERROR: missing argument(s)");
                        }
                        break;

                    default:
                        Console.Error.WriteLine("ERROR: invalid operation");
                        break;
                }
            //hook.ReturnPayload(dict);
            }
            else
                Console.WriteLine("ERROR: no Operation given");
        }
    }
}
