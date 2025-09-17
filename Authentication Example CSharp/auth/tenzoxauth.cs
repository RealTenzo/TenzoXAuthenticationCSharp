using System;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;

public class TenzoAuth
{
    private static readonly byte[] ebyte = new byte[]
    {
        0x1c,0x11,0x1a,0x0a,0x1c,0x4e,0x4a,0x41,0x0a,0x1d,0x1b,0x0f,0x0b,0x19,0x1b,
        0x59,0x07,0x0a,0x57,0x59,0x4d,0x5d,0x5e,0x49,0x42,0x10,0x00,0x08,0x1b,0x1a,
        0x18,0x11,0x43,0x08,0x1b,0x10,0x07,0x40,0x1b,0x1c,0x1d,0x04,0x43,0x09,0x00,
        0x01,0x11,0x06,0x1f,0x0e,0x07,0x11,0x5f,0x54,0x09,0x1d,0x17,0x0b,0x18,0x0e,
        0x07,0x00,0x0a,0x1b,0x1b,0x15,0x07,0x0f,0x09,0x0a,0x5a,0x04,0x1e,0x0a
    };
    private const string accses = "tenzo";
    private string CurrentUsername;
    private string CurrentHwid;
    private string CurrentApplication;
    private string CurrentSecret;
    private string cachedExpiryDate;
    private string lastStatusMessage;
    private bool lastLoginSuccess = false;
    private string currentVersion;
    private string DefaultApp;
    private string DefaultSecret;

    private static string GetApi()
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(accses);
        byte[] decryptedBytes = new byte[ebyte.Length];

        for (int i = 0; i < ebyte.Length; i++)
            decryptedBytes[i] = (byte)(ebyte[i] ^ keyBytes[i % keyBytes.Length]);

        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public TenzoAuth(string version, string app, string secret)
    {
        currentVersion = version;
        DefaultApp = app;
        DefaultSecret = secret;
        CurrentHwid = GetHWID();
        if (string.IsNullOrEmpty(DefaultApp) || string.IsNullOrEmpty(DefaultSecret))
        {
            lastStatusMessage = Messages.AppOrSecretEmpty;
        }
    }

    private static string ToLower(string s)
    {
        return s?.ToLowerInvariant() ?? string.Empty;
    }

    private static string GetHWID()
    {
        try
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity != null)
            {
                return identity.User?.Value ?? "UNKNOWN";
            }
        }
        catch { }
        return "UNKNOWN";
    }

    private string HttpGet(string url)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 10000;
            request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    return string.Empty;
                }

                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private bool HttpPut(string url, string data)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "PUT";
            request.ContentType = "application/json";
            request.Timeout = 10000;
            request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            byte[] bytes = Encoding.UTF8.GetBytes(data);
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(bytes, 0, bytes.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                return response.StatusCode == HttpStatusCode.OK;
            }
        }
        catch
        {
            return false;
        }
    }

    private bool HttpDelete(string url)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "DELETE";
            request.Timeout = 10000;
            request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                return response.StatusCode == HttpStatusCode.OK;
            }
        }
        catch
        {
            return false;
        }
    }

    private bool CheckApplicationVersion(string application, string secret)
    {
        if (string.IsNullOrEmpty(application) || string.IsNullOrEmpty(secret))
        {
            lastStatusMessage = Messages.AppOrSecretEmpty;
            return false;
        }

        string url = $"{GetApi()}/applications/{secret}/{application}.json";
        string jsonStr = HttpGet(url);

        if (string.IsNullOrEmpty(jsonStr) || jsonStr == "null")
        {
            lastStatusMessage = Messages.AppDataNotFound;
            return false;
        }

        try
        {
            var appData = JsonSerializer.Deserialize<JsonElement>(jsonStr);
            if (appData.TryGetProperty("applicationPaused", out JsonElement pausedElem) && pausedElem.GetBoolean())
            {
                lastStatusMessage = Messages.AppPaused;
                return false;
            }

            if (appData.TryGetProperty("version", out JsonElement versionElem))
            {
                string fetchedVersion = versionElem.GetString().Trim('"', ' ', '\r', '\n');
                if (fetchedVersion != currentVersion)
                {
                    lastStatusMessage = Messages.VersionMismatch;
                    return false;
                }
            }

            return true;
        }
        catch
        {
            lastStatusMessage = Messages.ErrorParsingAppData;
            return false;
        }
    }

    private bool IsDateExpired(string expiry)
    {
        if (expiry == "lifetime")
            return false;

        try
        {
            if (expiry.EndsWith("Z")) expiry = expiry.Substring(0, expiry.Length - 1);
            int dotPos = expiry.IndexOf('.');
            if (dotPos >= 0) expiry = expiry.Substring(0, dotPos);

            DateTime expiryTime = DateTime.ParseExact(expiry, "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            return expiryTime < DateTime.UtcNow;
        }
        catch
        {
            lastStatusMessage = Messages.InvalidExpiryFormat;
            return true;
        }
    }

    public bool CheckVersion(string application, string secret)
    {
        return CheckApplicationVersion(application, secret);
    }

    public bool CheckVersion()
    {
        return CheckVersion(DefaultApp, DefaultSecret);
    }

    public string GetExpiryDate()
    {
        if (!IsLoggedIn())
        {
            lastStatusMessage = Messages.NotLoggedIn;
            return "";
        }

        string url = $"{GetApi()}/applications/{CurrentSecret}/{CurrentApplication}/users/{CurrentUsername}/expiry.json";
        string jsonStr = HttpGet(url);

        if (string.IsNullOrEmpty(jsonStr) || jsonStr == "null")
            return "lifetime";

        jsonStr = jsonStr.Trim('"');
        return string.IsNullOrEmpty(jsonStr) ? "lifetime" : jsonStr;
    }

    public bool Login(string application, string secret, string username, string password)
    {
        lastLoginSuccess = false;
        string appUrl = $"{GetApi()}/applications/{secret}/{application}.json";
        string appJson = HttpGet(appUrl);

        if (string.IsNullOrEmpty(appJson) || appJson == "null")
        {
            lastStatusMessage = Messages.AppNotFound;
            return false;
        }

        var appData = JsonSerializer.Deserialize<JsonElement>(appJson);
        if (appData.TryGetProperty("applicationPaused", out JsonElement pausedElem) && pausedElem.GetBoolean())
        {
            lastStatusMessage = Messages.AppPaused;
            return false;
        }

        if (appData.TryGetProperty("version", out JsonElement versionElem))
        {
            string fetchedVersion = versionElem.GetString().Trim('"', ' ', '\r', '\n');
            if (fetchedVersion != currentVersion)
            {
                lastStatusMessage = Messages.VersionMismatch;
                return false;
            }
        }

        string usernameLower = ToLower(username);
        string url = $"{GetApi()}/applications/{secret}/{application}/users/{usernameLower}.json";
        string jsonStr = HttpGet(url);

        if (string.IsNullOrEmpty(jsonStr) || jsonStr == "null")
        {
            lastStatusMessage = Messages.UserNotFound;
            return false;
        }

        var user = JsonSerializer.Deserialize<JsonElement>(jsonStr);

        if (user.TryGetProperty("isBanned", out JsonElement bannedElem) && bannedElem.GetBoolean())
        {
            lastStatusMessage = Messages.UserBanned;
            return false;
        }
        if (!user.TryGetProperty("password", out JsonElement pwdElem) || pwdElem.GetString() != password)
        {
            lastStatusMessage = Messages.InvalidPassword;
            return false;
        }

        string expiry = "lifetime";
        if (user.TryGetProperty("expiry", out JsonElement expiryElem) && expiryElem.ValueKind != JsonValueKind.Null)
            expiry = expiryElem.GetString();

        if (IsDateExpired(expiry))
        {
            lastStatusMessage = Messages.SubscriptionExpired;
            return false;
        }

        bool hwidLock = user.TryGetProperty("hwidLock", out JsonElement hwidLockElem) && hwidLockElem.GetBoolean();
        string sid = user.TryGetProperty("sid", out JsonElement sidElem) && sidElem.ValueKind != JsonValueKind.Null
            ? sidElem.GetString()
            : "";

        if (!hwidLock || string.IsNullOrEmpty(sid) || sid == CurrentHwid)
        {
            if (hwidLock && string.IsNullOrEmpty(sid))
            {
                var obj = new JsonObject
                {
                    ["password"] = password,
                    ["expiry"] = expiry,
                    ["hwidLock"] = hwidLock,
                    ["sid"] = CurrentHwid
                };
                if (user.TryGetProperty("oneTime", out JsonElement oneTimeElem))
                    obj["oneTime"] = oneTimeElem.GetBoolean();

                string updatedJson = JsonSerializer.Serialize(obj);
                HttpPut(url, updatedJson);
            }

            CurrentUsername = username;
            CurrentApplication = application;
            CurrentSecret = secret;
            lastStatusMessage = Messages.LoginSuccessful;
            lastLoginSuccess = true;
            if (user.TryGetProperty("oneTime", out JsonElement oneTimeElem2) && oneTimeElem2.GetBoolean())
            {
                HttpDelete(url);
            }

            return true;
        }

        lastStatusMessage = Messages.HwidMismatch;
        return false;
    }

    public bool Login(string username, string password)
    {
        return Login(DefaultApp, DefaultSecret, username, password);
    }

    public bool Register(string username, string password, string license)
    {
        lastLoginSuccess = false;
        string usernameLower = ToLower(username);
        string licenseKey = license.Trim();

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(license))
        {
            lastStatusMessage = Messages.MissingCredentials;
            return false;
        }

        if (!CheckApplicationVersion(DefaultApp, DefaultSecret))
        {
            return false;
        }

        string userUrl = $"{GetApi()}/applications/{DefaultSecret}/{DefaultApp}/users/{usernameLower}.json";
        string userJson = HttpGet(userUrl);
        if (!string.IsNullOrEmpty(userJson) && userJson != "null")
        {
            lastStatusMessage = Messages.UsernameExists;
            return false;
        }

        string licenseUrl = $"{GetApi()}/applications/{DefaultSecret}/{DefaultApp}/licenses/{licenseKey}.json";
        string licenseJson = HttpGet(licenseUrl);
        if (string.IsNullOrEmpty(licenseJson) || licenseJson == "null")
        {
            lastStatusMessage = string.Format(Messages.InvalidLicense, license);
            return false;
        }

        try
        {
            var licenseData = JsonSerializer.Deserialize<JsonElement>(licenseJson);
            if (licenseData.TryGetProperty("used", out JsonElement usedElem) && usedElem.GetBoolean())
            {
                lastStatusMessage = string.Format(Messages.LicenseUsed, license);
                return false;
            }

            string expiry = "lifetime";
            if (licenseData.TryGetProperty("expiry", out JsonElement expiryElem) && expiryElem.ValueKind != JsonValueKind.Null)
                expiry = expiryElem.GetString();

            if (IsDateExpired(expiry))
            {
                lastStatusMessage = string.Format(Messages.LicenseExpired, license);
                return false;
            }

            bool oneTimeUse = licenseData.TryGetProperty("oneTime", out JsonElement oneTimeElem) && oneTimeElem.GetBoolean();

            var userData = new JsonObject
            {
                ["password"] = password,
                ["expiry"] = expiry,
                ["hwidLock"] = true,
                ["sid"] = CurrentHwid,
                ["isBanned"] = false,
                ["createdAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture)
            };
            if (oneTimeUse)
                userData["oneTime"] = true;

            string userJsonData = JsonSerializer.Serialize(userData);
            if (!HttpPut(userUrl, userJsonData))
            {
                lastStatusMessage = Messages.FailedCreateUser;
                return false;
            }

            var licenseUpdate = new JsonObject
            {
                ["used"] = true,
                ["associatedUser"] = usernameLower,
                ["expiry"] = expiry
            };
            if (licenseData.TryGetProperty("displayName", out JsonElement displayNameElem))
                licenseUpdate["displayName"] = displayNameElem.GetString();

            string licenseJsonData = JsonSerializer.Serialize(licenseUpdate);
            if (!HttpPut(licenseUrl, licenseJsonData))
            {
                HttpDelete(userUrl);
                lastStatusMessage = string.Format(Messages.FailedUpdateLicense, license);
                return false;
            }

            if (oneTimeUse)
            {
                HttpDelete(licenseUrl);
            }

            CurrentUsername = username;
            CurrentApplication = DefaultApp;
            CurrentSecret = DefaultSecret;
            lastStatusMessage = Messages.RegistrationSuccessful;
            lastLoginSuccess = true;
            return true;
        }
        catch
        {
            lastStatusMessage = Messages.ErrorDuringRegistration;
            return false;
        }
    }

    public string GetLastStatusMessage() => lastStatusMessage;

    public bool GetLastLoginSuccess() => lastLoginSuccess;

    public string GetCurrentUsername() => CurrentUsername;

    public string GetCurrentApplication() => CurrentApplication;

    public bool IsLoggedIn() => !string.IsNullOrEmpty(CurrentUsername) && !string.IsNullOrEmpty(CurrentApplication);

    public string GetCurrentVersion() => currentVersion;
}