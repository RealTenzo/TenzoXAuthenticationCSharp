using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace TXAAuth
{
    public class TXA
    {
        public string AppName { get; private set; }
        public string Secret { get; private set; }
        public string Version { get; private set; }

        private readonly string ApiUrl = "https://tenxoxauthentication.qzz.io";
        private readonly HttpClient client = new HttpClient();

        public bool IsInitialized { get; private set; } = false;
        public bool IsLoggedIn { get; private set; } = false;
        public UserData User { get; private set; }
        public string ResponseMessage { get; private set; } = "";

        // Simplified property access
        public string Response { get { return ResponseMessage; } }
        public string this[string name] { get { return Var(name); } }

        public Dictionary<string, string> Variables { get; private set; } = new Dictionary<string, string>();
        public bool IsApplicationActive { get; private set; } = false;
        public bool IsVersionCorrect { get; private set; } = false;
        public string ServerVersion { get; private set; } = "";

        // Import Windows API functions for console
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        private static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);
        public TXA(string name, string secret, string version)
        {
            AppName = name;
            Secret = secret;
            Version = version;
        }

        public void Init()
        {
            if (string.IsNullOrEmpty(AppName) || string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Version))
            {
                ShowError("TXA Auth Error", "AppName/Secret/Version missing");
                Environment.Exit(0);
            }

            // Run initialization in a background task
            var initTask = Task.Run(async () =>
            {
                try
                {
                    bool paused = await CheckIfPaused();
                    if (paused)
                    {
                        ShowError("Application Paused", "Application is currently paused by administrator");
                        Environment.Exit(0);
                    }

                    IsApplicationActive = !paused;

                    var versionCheck = await CheckVersionWithDetails();
                    IsVersionCorrect = versionCheck.isValid;
                    ServerVersion = versionCheck.serverVersion;

                    if (!IsVersionCorrect)
                    {
                        ShowError("Update Required",
                            $"Version mismatch!\n\nYour version: {Version}\nServer version: {ServerVersion}\n\nPlease update to the latest version.");
                        Environment.Exit(0);
                    }

                    await LoadApplicationVariables();

                    IsInitialized = true;
                    ResponseMessage = "TXA SDK Initialized successfully!";
                }
                catch (Exception ex)
                {
                    ShowError("Init Error", $"Initialization failed: {ex.Message}");
                    Environment.Exit(0);
                }
            });
        }

        private void ShowError(string title, string message)
        {
            HideAllWindows();
            AllocConsole();
            IntPtr consoleHandle = GetConsoleWindow();
            if (consoleHandle != IntPtr.Zero)
            {
                ShowWindow(consoleHandle, SW_SHOW);
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n╔{new string('═', 70)}╗");
            Console.WriteLine($"║ {title.PadRight(69)} ║");
            Console.WriteLine($"╠{new string('═', 70)}╣");

            string[] lines = message.Split('\n');
            foreach (string line in lines)
            {
                Console.WriteLine($"║ {line.PadRight(69)} ║");
            }

            Console.WriteLine($"╚{new string('═', 70)}╝");
            Console.ResetColor();
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();

            FreeConsole();
        }
    
        private void HideAllWindows()
        {

          int currentProcessId = Process.GetCurrentProcess().Id;
          EnumWindows((hWnd, lParam) =>
          {

              GetWindowThreadProcessId(hWnd, out int processId);
              if (processId == currentProcessId && IsWindowVisible(hWnd))
              {
                   
                  ShowWindow(hWnd, SW_HIDE);
              
              }
              return true;
           
          }, IntPtr.Zero);
        }

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int processId);

        public async Task<LoginResult> Login(string username, string password)
        {
            ResponseMessage = "";
            var loginResult = new LoginResult();

            if (!IsInitialized)
            {
                ResponseMessage = "Error: Call TXA.Init() first";
                loginResult.Success = false;
                loginResult.Message = ResponseMessage;
                return loginResult;
            }

            try
            {
                string hwid = GetHWID();
                var payload = new
                {
                    username,
                    password,
                    secret = Secret,
                    appName = AppName,
                    appVersion = Version,
                    hwid
                };

                var response = await SendRequest("login", payload);

                if (response.Success)
                {
                    IsLoggedIn = true;

                    string GetVal(string key)
                    {
                        if (response.Data.ContainsKey(key) && response.Data[key] is JsonElement el)
                            return el.ValueKind == JsonValueKind.String ? el.GetString() : el.ToString();
                        return null;
                    }

                    User = new UserData
                    {
                        Username = GetVal("username"),
                        Subscription = GetVal("subscription"),
                        Expiry = GetVal("expiry")
                    };

                    await LoadUserVariables();
                    ResponseMessage = $"Login successful! Welcome, {User.Username}";

                    loginResult.Success = true;
                    loginResult.Message = ResponseMessage;
                    loginResult.User = User;
                    return loginResult;
                }
                else
                {
                    string errorMessage = response.Message;
                    string formattedMessage;

                    if (errorMessage.Contains("INVALID_CREDENTIALS") ||
                        errorMessage.Contains("Invalid username or password"))
                    {
                        formattedMessage = "Invalid username or password";
                    }
                    else if (errorMessage.Contains("HWID_RESET") ||
                             errorMessage.Contains("HWID_MISMATCH"))
                    {
                        formattedMessage = "HWID mismatch. Please contact support to reset your HWID";
                    }
                    else if (errorMessage.Contains("BANNED") ||
                             errorMessage.Contains("suspended"))
                    {
                        formattedMessage = "Account has been banned or suspended";
                    }
                    else if (errorMessage.Contains("expired") ||
                             errorMessage.Contains("EXPIRED"))
                    {
                        formattedMessage = "Subscription has expired";
                    }
                    else if (errorMessage.Contains("MAX_DEVICES"))
                    {
                        formattedMessage = "Maximum number of devices reached";
                    }
                    else
                    {
                        formattedMessage = $"Login failed: {response.Message}";
                    }

                    ResponseMessage = formattedMessage;
                    loginResult.Success = false;
                    loginResult.Message = formattedMessage;
                    return loginResult;
                }
            }
            catch (Exception ex)
            {
                ResponseMessage = $"Connection error: {ex.Message}";
                loginResult.Success = false;
                loginResult.Message = ResponseMessage;
                return loginResult;
            }
        }

    
    
        public async Task<RegisterResult> Register(string username, string password, string license)
        {
            ResponseMessage = "";
            var registerResult = new RegisterResult();

            if (!IsInitialized)
            {
                ResponseMessage = "Error: Call TXA.Init() first";
                registerResult.Success = false;
                registerResult.Message = ResponseMessage;
                return registerResult;
            }

            try
            {
                string hwid = GetHWID();
                var payload = new
                {
                    username,
                    password,
                    licenseKey = license,
                    secret = Secret,
                    appName = AppName,
                    appVersion = Version,
                    hwid
                };

                var response = await SendRequest("register", payload);

                if (response.Success)
                {
                    ResponseMessage = "Registration successful! You can login now";
                    registerResult.Success = true;
                    registerResult.Message = ResponseMessage;
                    return registerResult;
                }
                else
                {
                    string errorMessage = response.Message;
                    string formattedMessage;

                    if (errorMessage.Contains("INVALID_LICENSE"))
                    {
                        formattedMessage = "Invalid license key";
                    }
                    else if (errorMessage.Contains("USERNAME_TAKEN"))
                    {
                        formattedMessage = "Username is already taken";
                    }
                    else if (errorMessage.Contains("LICENSE_USED"))
                    {
                        formattedMessage = "License key has already been used";
                    }
                    else if (errorMessage.Contains("LICENSE_EXPIRED"))
                    {
                        formattedMessage = "License key has expired";
                    }
                    else if (errorMessage.Contains("WEAK_PASSWORD"))
                    {
                        formattedMessage = "Password is too weak. Please use a stronger password";
                    }
                    else if (errorMessage.Contains("INVALID_USERNAME"))
                    {
                        formattedMessage = "Invalid username format";
                    }
                    else
                    {
                        formattedMessage = $"Registration failed: {response.Message}";
                    }

                    ResponseMessage = formattedMessage;
                    registerResult.Success = false;
                    registerResult.Message = formattedMessage;
                    return registerResult;
                }
            }
            catch (Exception ex)
            {
                ResponseMessage = $"Connection error: {ex.Message}";
                registerResult.Success = false;
                registerResult.Message = ResponseMessage;
                return registerResult;
            }
        }

   
        public string Var(string varName)
        {
            string val;
            if (Variables.TryGetValue(varName, out val))
            {
                return val;
            }
            return "VARIABLE_NOT_FOUND";
        }

        public T Get<T>(string varName)
        {
            string value = Var(varName);
            if (value == "VARIABLE_NOT_FOUND") return default(T);

            try
            {
                if (typeof(T) == typeof(bool))
                {
                    return (T)(object)(value.ToLower() == "true");
                }
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return default(T);
            }
        }

        public async Task<string> GetVariable(string varName)
        {
            ResponseMessage = "";

            if (!IsInitialized)
            {
                ResponseMessage = "Error: Call TXA.Init() first";
                return null;
            }

            if (Variables.ContainsKey(varName))
            {
                ResponseMessage = $"Variable '{varName}' retrieved from cache";
                return Variables[varName];
            }

            try
            {
                var payload = new
                {
                    secret = Secret,
                    appName = AppName,
                    appVersion = Version,
                    varName
                };

                var response = await SendRequest("getvariable", payload);

                if (response.Success)
                {
                    if (response.Data.ContainsKey("value") && response.Data["value"] is JsonElement valueElement)
                    {
                        string value = valueElement.ToString();
                        Variables[varName] = value;
                        ResponseMessage = $"Variable '{varName}' retrieved successfully";
                        return value;
                    }
                    ResponseMessage = $"Variable '{varName}' not found";
                    return null;
                }
                else
                {
                    if (response.Message != "VARIABLE_NOT_FOUND")
                    {
                        ResponseMessage = $"Failed to get variable '{varName}': {response.Message}";
                    }
                    else
                    {
                        ResponseMessage = $"Variable '{varName}' not found";
                    }
                    return null;
                }
            }
            catch (Exception ex)
            {
                ResponseMessage = $"Connection error: {ex.Message}";
                return null;
            }
        }

        public async Task<bool> RefreshVariables()
        {
            ResponseMessage = "";

            if (!IsInitialized)
            {
                ResponseMessage = "Error: Call TXA.Init() first";
                return false;
            }

            try
            {
                bool result = await LoadApplicationVariables();
                if (result)
                {
                    ResponseMessage = $"Successfully refreshed {Variables.Count} variables";
                    return true;
                }
                else
                {
                    ResponseMessage = "No variables found or failed to load";
                    return false;
                }
            }
            catch (Exception ex)
            {
                ResponseMessage = $"Failed to refresh variables: {ex.Message}";
                return false;
            }
        }

        private async Task<bool> CheckIfPaused()
        {
            var payload = new { secret = Secret, appName = AppName };
            var response = await SendRequest("isapplicationpaused", payload);
            return response.Success && response.Message == "APPLICATION_PAUSED";
        }

        private async Task<(bool isValid, string serverVersion)> CheckVersionWithDetails()
        {
            var payload = new { secret = Secret, appName = AppName, appVersion = Version };
            var response = await SendRequest("versioncheck", payload);

            if (response.Success)
            {
                if (response.Message == "VERSION_OK")
                {
                    return (true, Version);
                }
                else if (response.Message == "VERSION_MISMATCH")
                {
                    if (response.Data.ContainsKey("serverVersion") && response.Data["serverVersion"] is JsonElement serverVersionElement)
                    {
                        return (false, serverVersionElement.GetString());
                    }
                    return (false, "Unknown");
                }
            }
            return (false, "Unknown");
        }

        private async Task<bool> LoadApplicationVariables()
        {
            try
            {
                var payload = new { secret = Secret, appName = AppName };
                var response = await SendRequest("getvariables", payload);

                if (response.Success && response.Message != "NO_VARIABLES")
                {
                    if (response.Data.ContainsKey("variables") && response.Data["variables"] is JsonElement variablesElement)
                    {
                        Variables.Clear();

                        if (variablesElement.ValueKind == JsonValueKind.Object)
                        {
                            foreach (var prop in variablesElement.EnumerateObject())
                            {
                                Variables[prop.Name] = prop.Value.ToString();
                            }
                        }
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private async Task LoadUserVariables()
        {
            if (IsLoggedIn && User != null)
            {
                string userSettings = await GetVariable($"user_{User.Username}_settings");
                if (!string.IsNullOrEmpty(userSettings))
                {
                    Console.WriteLine($"Loaded user settings for {User.Username}");
                }

                string permissions = await GetVariable($"permissions_{User.Subscription}");
                if (!string.IsNullOrEmpty(permissions))
                {
                    Console.WriteLine($"Loaded permissions for subscription: {User.Subscription}");
                }
            }
        }

        private static string GetHWID()
        {
            try
            {
                string sid = WindowsIdentity.GetCurrent().User.Value;
                return sid;
            }
            catch (Exception)
            {
                return "HWID_FAIL";
            }
        }

        private async Task<ApiResponse> SendRequest(string endpoint, object payload)
        {
            string json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var result = await client.PostAsync($"{ApiUrl}/{endpoint}", content);
            string responseBody = await result.Content.ReadAsStringAsync();

            try
            {
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                return JsonSerializer.Deserialize<ApiResponse>(responseBody, options);
            }
            catch
            {
                return new ApiResponse { Success = false, Message = "Invalid response from server" };
            }
        }

   
        public class LoginResult
        {
            public bool Success { get; set; }
            public string Message { get; set; }
            public UserData User { get; set; }
        }

        public class RegisterResult
        {
            public bool Success { get; set; }
            public string Message { get; set; }
        }

        public class ApiResponse
        {
            [JsonPropertyName("success")]
            public bool Success { get; set; }

            [JsonPropertyName("message")]
            public string Message { get; set; }

            [JsonExtensionData]
            public Dictionary<string, object> Data { get; set; }
        }

        public class UserData
        {
            public string Username { get; set; }
            public string Subscription { get; set; }
            public string Expiry { get; set; }
        }
    }
}