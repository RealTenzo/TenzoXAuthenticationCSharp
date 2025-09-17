# TenzoXAuthenticationCSharp

**TenzoXAuthenticationCSharp** is a simple C# library for adding **authentication and licensing** functionality to your applications. It provides **login, registration, license validation, and version checking** features in a few lines of code. Ideal for developers who want to secure their apps with minimal effort.

**Website:** [https://txabeta.netlify.app/](https://txabeta.netlify.app/)

## Features

* Login with username and password
* Registration with license keys
* Version checking to prevent outdated app usage
* Expiry date and user info retrieval
* Simple and clean C# integration

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/TenzoXAuthenticationCSharp.git
```

2. Include `TenzoAuth.cs` and `message.cs` in your project.


## Usage Example

```csharp
// Initialize auth
TenzoAuth auth = new TenzoAuth("1.0", "AppName", "SecretKey");

// Login
if(auth.Login("username", "password"))
{
    Console.WriteLine($"Login successful!\nUser: {auth.GetCurrentUsername()}\nExpiry: {auth.GetExpiryDate()}");
}
else
{
    Console.WriteLine("Login failed: " + auth.GetLastStatusMessage());
}

// Register
if(auth.Register("username", "password", "license"))
{
    Console.WriteLine($"Registration successful!\nUser: {auth.GetCurrentUsername()}\nExpiry: {auth.GetExpiryDate()}");
}
else
{
    Console.WriteLine("Registration failed: " + auth.GetLastStatusMessage());
}
```

## Notes

* Ensure your app version matches the version expected by the library.
* License keys can be pre-generated or dynamically created by your system.
* Works with both **WinForms** and **console applications**.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for bug fixes or new features.

## License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
