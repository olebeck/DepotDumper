using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Linq;
using SteamKit2;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DepotDumper
{

    class Program
    {
        public static StreamWriter sw;
        public static StreamWriter sw2;
        private static Steam3Session steam3;
        private static string user;
        private static ConsoleColor color;
        private static uint BlockedDepots = 0;
        private static uint DeniedDepots = 0;
        private static uint timeoutDepots = 0;
        private static uint OkDepots = 0;

        static bool login()
        {
            Console.Write("Enter your Steam username: ");
            user = Console.ReadLine();
            string password;

            Console.Write("Enter your Steam Password: ");
            if (Console.IsInputRedirected)
            {
                password = Console.ReadLine();
            }
            else
            {
                // Avoid console echoing of password
                password = Util.ReadPassword();
                Console.WriteLine();
            }

            Config.SuppliedPassword = password;
            AccountSettingsStore.LoadFromFile("xxx");

            steam3 = new Steam3Session(
               new SteamUser.LogOnDetails()
               {
                   Username = user,
                   Password = password,
                   ShouldRememberPassword = false,
                   LoginID = 0x534B32, // "SK2"
               }
            );

            var steam3Credentials = steam3.WaitForCredentials();

            if (!steam3Credentials.IsValid)
            {
                Console.WriteLine("Unable to get steam3 credentials.");
                return false;
            }
            return true;
        }

        static async Task<int> Main(string[] args)
        {
            bool hasLoggedIn = login();
            if (!hasLoggedIn)
            {
                Console.WriteLine("failed to login");
                Console.ReadKey();
                return 1;
            }

            Console.WriteLine("Waiting for licenses...\n");
            steam3.WaitUntilCallback(() => { }, () => { return steam3.Licenses != null; });
            Console.Write($"You have {steam3.Licenses.Count} licenses ");

            // get app infos
            IEnumerable<uint> licenseQuery;
            licenseQuery = steam3.Licenses.Select(x => x.PackageID).Distinct();
            await steam3.RequestPackageInfo(licenseQuery);

            List<uint> appIds = new List<uint>();
            uint LicensesWithoutToken = 0;

            // get appids in packages
            foreach (var license in licenseQuery)
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo package;
                if (steam3.PackageInfo.TryGetValue(license, out package) && package != null)
                {
                    if(package.MissingToken)
                    {
                        LicensesWithoutToken++;
                        continue;
                    }
                    IEnumerable<uint> PackageAppIds = package.KeyValues["appids"].Children.Select(appId => appId.AsUnsignedInteger());
                    appIds = appIds.Concat(PackageAppIds).ToList();
                }
            }
            Console.WriteLine($"({steam3.Licenses.Count - LicensesWithoutToken} of them have a token)\n");
            Console.WriteLine($"You own {appIds.Count} apps\n");

            // get depot, app keys and info
            await ProcessApps(appIds);


            sw = new StreamWriter($"{user}_steam.depotkeys");
            sw.AutoFlush = true;
            foreach (var Depot in steam3.DepotKeys)
            {
                uint DepotID = Depot.Key;
                string DepotKeyHex = string.Concat(Depot.Value.Select(b => b.ToString("X2")).ToArray());
                sw.WriteLine($"{ DepotID };{ DepotKeyHex }");
            }
            sw.Close();


            sw2 = new StreamWriter($"{user}_steam.appkeys");
            sw2.AutoFlush = true;
            foreach (var app in steam3.AppInfo)
            {
                ulong appToken = 0;
                steam3.AppTokens.TryGetValue(app.Key, out appToken);
                sw2.WriteLine($"{ app.Key };{ GetAppName(app.Value) };{ appToken }");
            }
            sw2.Close();

            color = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            // Console.WriteLine($"\n\nSub tokens: "); /* not doing package tokens */
            Console.WriteLine($"\n\nApp tokens: {steam3.AppTokens.Count}");
            Console.WriteLine($"Depot keys: {steam3.DepotKeys.Count} (Timeout={timeoutDepots} - OK={OkDepots} Accessdenied={DeniedDepots} - Blocked={BlockedDepots}\n");
            Console.ForegroundColor = color;

            Console.WriteLine("\nExiting...");
            steam3.Disconnect();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return 0;
        }

        private static async Task ProcessApps(List<uint> appIds)
        {
            appIds = appIds.Distinct().ToList();
            await steam3.RequestAppTokens(appIds);

            Console.WriteLine($"App tokens granted: { steam3.AppTokens.Count } - Denied: { steam3.AppTokensDenied.Count } - Non-zero: { steam3.AppTokens.Where(e => e.Value != 0).Count() }\n");

            await steam3.RequestAppInfos(appIds);
            List<Task<SteamApps.DepotKeyCallback>> GetKeyTasks = new List<Task<SteamApps.DepotKeyCallback>>();

            foreach (uint appId in appIds)
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo app;
                if (!steam3.AppInfo.TryGetValue(appId, out app) || app == null)
                {
                    continue;
                }

                KeyValue appinfo = app.KeyValues;
                KeyValue depots = appinfo.Children.Where(c => c.Name == "depots").FirstOrDefault();
                KeyValue config = appinfo.Children.Where(c => c.Name == "config").FirstOrDefault();


                if (depots == null)
                {
                    continue;
                }

                foreach (var depotSection in depots.Children)
                {
                    uint id = uint.MaxValue;

                    if (!uint.TryParse(depotSection.Name, out id) || id == uint.MaxValue)
                        continue;

                    if (depotSection.Children.Count == 0)
                        continue;

                    if (config == KeyValue.Invalid)
                        continue;

                    if (!await AccountHasAccess(id))
                        continue;

                    GetKeyTasks.Add(steam3.TryRequestDepotKey(id, appId));
                }
            }

            await Task.WhenAll(GetKeyTasks);

            foreach (var keyTask in GetKeyTasks )
            {
                var Depot = await keyTask;
                if (Depot == null)
                {
                    continue;
                }

                if (Depot.Result == EResult.OK)
                {
                    OkDepots++;
                    steam3.DepotKeys[Depot.DepotID] = Depot.DepotKey;
                }
                else if (Depot.Result == EResult.Blocked)
                {
                    BlockedDepots++;
                }
                else if (Depot.Result == EResult.AccessDenied)
                {
                    DeniedDepots++;
                }
                else if (Depot.Result == EResult.Timeout)
                {
                    timeoutDepots++;
                }
            }
        }
        
        static async Task<bool> AccountHasAccess( uint depotId )
        {
            IEnumerable<uint> licenseQuery = steam3.Licenses.Select(x => x.PackageID).Distinct();
            await steam3.RequestPackageInfo(licenseQuery);

            foreach (var license in licenseQuery)
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo package;
                if (steam3.PackageInfo.TryGetValue(license, out package) && package != null)
                {
                    if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;

                    if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;
                }
            }

            return false;
        }

        static string GetAppName(SteamApps.PICSProductInfoCallback.PICSProductInfo appinfo)
        {
            KeyValue common = appinfo.KeyValues.Children.Where(c => c.Name == "common").FirstOrDefault();
            string appName = "** UNKNOWN **";
            if (common != null)
            {
                KeyValue nameKV = common.Children.Where(c => c.Name == "name").FirstOrDefault();
                if (nameKV != null)
                {
                    appName = nameKV.AsString();
                }
            }
            return appName;
        }
    }

}
