using SteamKit2;
using SteamKit2.Unified.Internal;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DepotDumper
{

    class Steam3Session
    {
        public class Credentials
        {
            public bool LoggedOn { get; set; }
            public ulong SessionToken { get; set; }

            public bool IsValid
            {
                get { return LoggedOn; }
            }
        }

        public ReadOnlyCollection<SteamApps.LicenseListCallback.License> Licenses
        {
            get;
            private set;
        }

        public Dictionary<uint, byte[]> AppTickets { get; private set; }
        public Dictionary<uint, ulong> AppTokens { get; private set; }
        public List<uint> AppTokensDenied { get; private set; }
        public Dictionary<uint, byte[]> DepotKeys { get; private set; }
        public ConcurrentDictionary<string, SteamApps.CDNAuthTokenCallback> CDNAuthTokens { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> AppInfo { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> PackageInfo { get; private set; }
        public Dictionary<string, byte[]> AppBetaPasswords { get; private set; }

        public SteamClient steamClient;
        public SteamUser steamUser;
        SteamApps steamApps;
        SteamUnifiedMessages.UnifiedService<IPublishedFile> steamPublishedFile;

        CallbackManager callbacks;

        bool authenticatedUser;
        bool bConnected;
        bool bConnecting;
        bool bAborted;
        bool bExpectingDisconnectRemote;
        bool bDidDisconnect;
        bool bDidReceiveLoginKey;
        int connectionBackoff;
        int seq; // more hack fixes
        DateTime connectTime;

        // input
        SteamUser.LogOnDetails logonDetails;

        // output
        Credentials credentials;

        static readonly TimeSpan STEAM3_TIMEOUT = TimeSpan.FromSeconds(30);
        static readonly CancellationTokenSource s_cts = new CancellationTokenSource();

        public Steam3Session(SteamUser.LogOnDetails details)
        {
            this.logonDetails = details;

            this.authenticatedUser = details.Username != null;
            this.credentials = new Credentials();
            this.bConnected = false;
            this.bConnecting = false;
            this.bAborted = false;
            this.bExpectingDisconnectRemote = false;
            this.bDidDisconnect = false;
            this.bDidReceiveLoginKey = false;
            this.seq = 0;

            this.AppTickets = new Dictionary<uint, byte[]>();
            this.AppTokens = new Dictionary<uint, ulong>();
            this.AppTokensDenied = new List<uint>();
            this.DepotKeys = new Dictionary<uint, byte[]>();
            this.CDNAuthTokens = new ConcurrentDictionary<string, SteamApps.CDNAuthTokenCallback>();
            this.AppInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            this.PackageInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            this.AppBetaPasswords = new Dictionary<string, byte[]>();

            this.steamClient = new SteamClient();

            this.steamUser = this.steamClient.GetHandler<SteamUser>();
            this.steamApps = this.steamClient.GetHandler<SteamApps>();
            var steamUnifiedMessages = this.steamClient.GetHandler<SteamUnifiedMessages>();
            this.steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>();

            this.callbacks = new CallbackManager(this.steamClient);

            this.callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
            this.callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
            this.callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
            this.callbacks.Subscribe<SteamUser.SessionTokenCallback>(SessionTokenCallback);
            this.callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);
            this.callbacks.Subscribe<SteamUser.UpdateMachineAuthCallback>(UpdateMachineAuthCallback);
            this.callbacks.Subscribe<SteamUser.LoginKeyCallback>(LoginKeyCallback);

            Console.Write("Connecting to Steam3...");

            if (authenticatedUser)
            {
                FileInfo fi = new FileInfo(String.Format("{0}.sentryFile", logonDetails.Username));
                if (AccountSettingsStore.Instance.SentryData != null && AccountSettingsStore.Instance.SentryData.ContainsKey(logonDetails.Username))
                {
                    logonDetails.SentryFileHash = Util.SHAHash(AccountSettingsStore.Instance.SentryData[logonDetails.Username]);
                }
                else if (fi.Exists && fi.Length > 0)
                {
                    var sentryData = File.ReadAllBytes(fi.FullName);
                    logonDetails.SentryFileHash = Util.SHAHash(sentryData);
                    AccountSettingsStore.Instance.SentryData[logonDetails.Username] = sentryData;
                    AccountSettingsStore.Save();
                }
            }

            Connect();
        }
        class AppInfoTaskRes
        {
            public int hash;
            public IEnumerable<SteamApps.PICSProductInfoCallback> res;
            public AppInfoTaskRes(int hash, IEnumerable<SteamApps.PICSProductInfoCallback> res)
            {
                this.hash = hash;
                this.res = res;
            }
        }

        public delegate bool WaitCondition();
        public bool WaitUntilCallback(Action submitter, WaitCondition waiter)
        {
            while (!bAborted && !waiter())
            {
                submitter();

                int seq = this.seq;
                do
                {
                    WaitForCallbacks();
                }
                while (!bAborted && this.seq == seq && !waiter());
            }

            return bAborted;
        }

        public Credentials WaitForCredentials()
        {
            if (credentials.IsValid || bAborted)
                return credentials;

            WaitUntilCallback(() => { }, () => { return credentials.IsValid; });

            return credentials;
        }

        public async Task<Dictionary<uint, ulong>> RequestAppTokens(IEnumerable<uint> appIds)
        {
            appIds = appIds.Distinct().Where(e => !AppTokens.ContainsKey(e));
            var job = steamApps.PICSGetAccessTokens(appIds, new List<uint>() { });
            job.Timeout = TimeSpan.FromSeconds(60);
            var Tokens = await job;

            AppTokensDenied = AppTokensDenied.Concat(Tokens.AppTokensDenied).ToList();
            foreach (var apptoken in Tokens.AppTokens)
            {
                if (!AppTokens.ContainsKey(apptoken.Key))
                    AppTokens.Add(apptoken.Key, apptoken.Value);
            }
            return AppTokens;
        }
        private async Task<AppInfoTaskRes> RequestAppInfoChunks(IEnumerable<uint> appIds)
        {
            var requests = appIds.Select(appId => new SteamApps.PICSRequest(appId));
            requests.Select(request =>
            {
                request.AccessToken = AppTokens[request.ID];
                request.Public = false;
                return request;
            });
            var appInfos = await steamApps.PICSGetProductInfo(requests, new List<SteamApps.PICSRequest>() { });
            return new AppInfoTaskRes(appIds.GetHashCode(), appInfos.Results);
        }

        public async Task RequestAppInfos(IEnumerable<uint> appIds)
        {
            var Chunks = Util.SplitList(appIds);
            int totalTasks = Chunks.Count();
            List<uint> depotsSeen = new List<uint>();

            var tasks = new Dictionary<int, Task<AppInfoTaskRes>>();
            foreach (IEnumerable<uint> ChunkAppIds in Chunks)
            {
                tasks.Add(ChunkAppIds.GetHashCode(), RequestAppInfoChunks(ChunkAppIds));
            }

            uint i = 0;
            while (tasks.Count > 0)
            {
                var appInfos = await await Task.WhenAny(tasks.Values);
                tasks.Remove(appInfos.hash);
                i++;

                Console.Write("\r" + new String(' ', Console.BufferWidth) + "\r");
                Console.Write($"App info Request {i} of {Chunks.Count()} - {depotsSeen.Count} depot keys");
                
                foreach (var AppInfoRes in appInfos.res)
                {
                    foreach (var app in AppInfoRes.Apps.Values)
                    {
                        if (AppInfo.ContainsKey(app.ID))
                            continue;
                        AppInfo.Add(app.ID, app);

                        KeyValue depots = app.KeyValues.Children.Where(c => c.Name == "depots").FirstOrDefault();
                        if (depots == null)
                            continue;
                        foreach (var depotSection in depots.Children)
                        {
                            uint id = uint.MaxValue;
                            if (!uint.TryParse(depotSection.Name, out id) || id == uint.MaxValue)
                                continue;
                            if(!depotsSeen.Contains(id))
                                depotsSeen.Add(id);
                        }
                    }

                    foreach (uint appId in AppInfoRes.UnknownApps)
                    {
                        AppInfo.TryAdd(appId, null);
                    }
                }
            }
        }

        public async Task RequestPackageInfo(IEnumerable<uint> packageIds)
        {
            List<uint> packages = packageIds.ToList();
            packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

            if (packages.Count == 0 || bAborted)
                return;

            var packageInfos = await steamApps.PICSGetProductInfo(new List<uint>(), packages);
            foreach(SteamApps.PICSProductInfoCallback packageInfo in packageInfos.Results)
            {
                foreach (var package_value in packageInfo.Packages)
                {
                    var package = package_value.Value;
                    PackageInfo.Add(package.ID, package);
                }

                foreach (var package in packageInfo.UnknownPackages)
                {
                    PackageInfo.Add(package, null);
                }
            }
        }

        public bool RequestFreeAppLicense(uint appId)
        {
            bool success = false;
            bool completed = false;
            Action<SteamApps.FreeLicenseCallback> cbMethod = (resultInfo) =>
            {
                completed = true;
                success = resultInfo.GrantedApps.Contains(appId);
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod);
            }, () => { return completed; });

            return success;
        }

        public void RequestAppTicket(uint appId)
        {
            if (AppTickets.ContainsKey(appId) || bAborted)
                return;


            if (!authenticatedUser)
            {
                AppTickets[appId] = null;
                return;
            }

            bool completed = false;
            Action<SteamApps.AppOwnershipTicketCallback> cbMethod = (appTicket) =>
            {
                completed = true;

                if (appTicket.Result != EResult.OK)
                {
                    Console.WriteLine("Unable to get appticket for {0}: {1}", appTicket.AppID, appTicket.Result);
                    Abort();
                }
                else
                {
                    Console.WriteLine("Got appticket for {0}!", appTicket.AppID);
                    AppTickets[appTicket.AppID] = appTicket.Ticket;
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.GetAppOwnershipTicket(appId), cbMethod);
            }, () => { return completed; });
        }

        public async Task<SteamApps.DepotKeyCallback> RequestDepotKey(uint depotId, uint appid = 0)
        {
            if (DepotKeys.ContainsKey(depotId) || bAborted)
                return null;

            SteamApps.DepotKeyCallback depotKey = await steamApps.GetDepotDecryptionKey(depotId, appid);

            if ( new List<SteamKit2.EResult>() { EResult.Timeout, EResult.AccessDenied, EResult.Blocked, EResult.OK }.Contains(depotKey.Result) )
            {
                return depotKey;
            }
            else
            {
                Abort();
                return null;
            }
        }

        public async Task<SteamApps.DepotKeyCallback> TryRequestDepotKey(uint depotId, uint appid = 0)
        {
            SteamApps.DepotKeyCallback depotkey = null;
            int attempt = 1;
            while (depotkey == null && attempt <= 3)
            {
                try
                {
                    s_cts.CancelAfter(5000);
                    depotkey = await RequestDepotKey(depotId, appid);
                }
                catch (TaskCanceledException)
                {
                }
                attempt++;
            }
            return depotkey;
        }

        public string ResolveCDNTopLevelHost(string host)
        {
            // SteamPipe CDN shares tokens with all hosts
            if (host.EndsWith(".steampipe.steamcontent.com"))
            {
                return "steampipe.steamcontent.com";
            }

            return host;
        }

        public void RequestCDNAuthToken(uint appid, uint depotid, string host)
        {
            host = ResolveCDNTopLevelHost(host);
            var cdnKey = string.Format("{0:D}:{1}", depotid, host);

            if (CDNAuthTokens.ContainsKey(cdnKey) || bAborted)
                return;

            bool completed = false;
            Action<SteamApps.CDNAuthTokenCallback> cbMethod = (cdnAuth) =>
            {
                completed = true;
                Console.WriteLine("Got CDN auth token for {0} result: {1} (expires {2})", host, cdnAuth.Result, cdnAuth.Expiration);

                if (cdnAuth.Result != EResult.OK)
                {
                    Abort();
                    return;
                }

                CDNAuthTokens.TryAdd(cdnKey, cdnAuth);
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.GetCDNAuthToken(appid, depotid, host), cbMethod);
            }, () => { return completed; });
        }

        public void CheckAppBetaPassword(uint appid, string password)
        {
            bool completed = false;
            Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = (appPassword) =>
            {
                completed = true;

                Console.WriteLine("Retrieved {0} beta keys with result: {1}", appPassword.BetaPasswords.Count, appPassword.Result);

                foreach (var entry in appPassword.BetaPasswords)
                {
                    AppBetaPasswords[entry.Key] = entry.Value;
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password), cbMethod);
            }, () => { return completed; });
        }

        public PublishedFileDetails GetPubfileDetails(PublishedFileID pubFile)
        {
            var pubFileRequest = new CPublishedFile_GetDetails_Request();
            pubFileRequest.publishedfileids.Add(pubFile);

            bool completed = false;
            PublishedFileDetails details = null;

            Action<SteamUnifiedMessages.ServiceMethodResponse> cbMethod = callback =>
            {
                completed = true;
                if (callback.Result == EResult.OK)
                {
                    var response = callback.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
                    details = response.publishedfiledetails[0];
                }
                else
                {
                    throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC id for pubfile {pubFile}.");
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod);
            }, () => { return completed; });

            return details;
        }

        void Connect()
        {
            bAborted = false;
            bConnected = false;
            bConnecting = true;
            connectionBackoff = 0;
            bExpectingDisconnectRemote = false;
            bDidDisconnect = false;
            bDidReceiveLoginKey = false;
            this.connectTime = DateTime.Now;
            this.steamClient.Connect();
        }

        private void Abort(bool sendLogOff = true)
        {
            Disconnect(sendLogOff);
        }
        public void Disconnect(bool sendLogOff = true)
        {
            if (sendLogOff)
            {
                steamUser.LogOff();
            }

            steamClient.Disconnect();
            bConnected = false;
            bConnecting = false;
            bAborted = true;

            // flush callbacks until our disconnected event
            while (!bDidDisconnect)
            {
                callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
            }
        }

        public void TryWaitForLoginKey()
        {
            if (logonDetails.Username == null || !DepotDumper.Config.RememberPassword) return;

            var totalWaitPeriod = DateTime.Now.AddSeconds(3);

            while (true)
            {
                DateTime now = DateTime.Now;
                if (now >= totalWaitPeriod) break;

                if (bDidReceiveLoginKey) break;

                callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
            }
        }

        private void WaitForCallbacks()
        {
            callbacks.RunWaitCallbacks(TimeSpan.FromSeconds(1));

            TimeSpan diff = DateTime.Now - connectTime;

            if (diff > STEAM3_TIMEOUT && !bConnected)
            {
                Console.WriteLine("Timeout connecting to Steam3.");
                Abort();

                return;
            }
        }

        private void ConnectedCallback(SteamClient.ConnectedCallback connected)
        {
            Console.WriteLine("\nConnected to Steam! Logging in...");
            bConnecting = false;
            bConnected = true;
            if (!authenticatedUser)
            {
                Console.Write("Logging anonymously into Steam3...");
                steamUser.LogOnAnonymous();
            }
            else
            {
                steamUser.LogOn(logonDetails);
            }
        }

        private void DisconnectedCallback(SteamClient.DisconnectedCallback disconnected)
        {
            bDidDisconnect = true;

            if (disconnected.UserInitiated || bExpectingDisconnectRemote)
            {
                //Console.WriteLine("Disconnected from Steam");
            }
            else if (connectionBackoff >= 10)
            {
                Console.WriteLine("Could not connect to Steam after 10 tries");
                Abort(false);
            }
            else if (!bAborted)
            {
                if (bConnecting)
                {
                    Console.WriteLine("Connection to Steam failed. Trying again");
                }
                else
                {
                    Console.WriteLine("Lost connection to Steam. Reconnecting");
                }

                Thread.Sleep(1000 * ++connectionBackoff);
                steamClient.Connect();
            }
        }

        private void LogOnCallback(SteamUser.LoggedOnCallback loggedOn)
        {
            bool isSteamGuard = loggedOn.Result == EResult.AccountLogonDenied;
            bool is2FA = loggedOn.Result == EResult.AccountLoginDeniedNeedTwoFactor;
            bool isLoginKey = DepotDumper.Config.RememberPassword && logonDetails.LoginKey != null && loggedOn.Result == EResult.InvalidPassword;

            if (isSteamGuard || is2FA || isLoginKey)
            {
                bExpectingDisconnectRemote = true;
                Abort(false);

                if (!isLoginKey)
                {
                    Console.WriteLine("This account is protected by Steam Guard.");
                }

                if (is2FA)
                {
                    Console.Write("Please enter your 2 factor auth code from your authenticator app: ");
                    logonDetails.TwoFactorCode = Console.ReadLine();
                }
                else if (isLoginKey)
                {
                    AccountSettingsStore.Instance.LoginKeys.Remove(logonDetails.Username);
                    AccountSettingsStore.Save();

                    logonDetails.LoginKey = null;

                    if (DepotDumper.Config.SuppliedPassword != null)
                    {
                        Console.WriteLine("Login key was expired. Connecting with supplied password.");
                        logonDetails.Password = DepotDumper.Config.SuppliedPassword;
                    }
                    else
                    {
                        Console.WriteLine("Login key was expired. Please enter your password: ");
                        logonDetails.Password = Util.ReadPassword();
                    }
                }
                else
                {
                    Console.Write("Please enter the authentication code sent to your email address: ");
                    logonDetails.AuthCode = Console.ReadLine();
                }

                Console.Write("Disconnected from Steam, reconnecting...");
                Connect();

                return;
            }
            else if (loggedOn.Result == EResult.ServiceUnavailable)
            {
                Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
                Abort(false);

                return;
            }
            else if (loggedOn.Result != EResult.OK)
            {
                Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
                Abort();

                return;
            }

            this.seq++;
            credentials.LoggedOn = true;

        }

        private void SessionTokenCallback(SteamUser.SessionTokenCallback sessionToken)
        {
            Console.WriteLine("Got session token!");
            credentials.SessionToken = sessionToken.SessionToken;
        }

        private void LicenseListCallback(SteamApps.LicenseListCallback licenseList)
        {
            if (licenseList.Result != EResult.OK)
            {
                Console.WriteLine("Unable to get license list: {0} ", licenseList.Result);
                Abort();

                return;
            }
            Licenses = licenseList.LicenseList;
        }

        private void UpdateMachineAuthCallback(SteamUser.UpdateMachineAuthCallback machineAuth)
        {
            byte[] hash = Util.SHAHash(machineAuth.Data);
            // Console.WriteLine("Got Machine Auth: {0} {1} {2} {3}", machineAuth.FileName, machineAuth.Offset, machineAuth.BytesToWrite, machineAuth.Data.Length, hash);

            AccountSettingsStore.Instance.SentryData[logonDetails.Username] = machineAuth.Data;
            AccountSettingsStore.Save();

            var authResponse = new SteamUser.MachineAuthDetails
            {
                BytesWritten = machineAuth.BytesToWrite,
                FileName = machineAuth.FileName,
                FileSize = machineAuth.BytesToWrite,
                Offset = machineAuth.Offset,

                SentryFileHash = hash, // should be the sha1 hash of the sentry file we just wrote

                OneTimePassword = machineAuth.OneTimePassword, // not sure on this one yet, since we've had no examples of steam using OTPs

                LastError = 0, // result from win32 GetLastError
                Result = EResult.OK, // if everything went okay, otherwise ~who knows~

                JobID = machineAuth.JobID, // so we respond to the correct server job
            };

            // send off our response
            steamUser.SendMachineAuthResponse(authResponse);
        }

        private void LoginKeyCallback(SteamUser.LoginKeyCallback loginKey)
        {
            Console.WriteLine("Accepted new login key for account {0}", logonDetails.Username);

            AccountSettingsStore.Instance.LoginKeys[logonDetails.Username] = loginKey.LoginKey;
            AccountSettingsStore.Save();

            steamUser.AcceptNewLoginKey(loginKey);

            bDidReceiveLoginKey = true;
        }
    }
}
