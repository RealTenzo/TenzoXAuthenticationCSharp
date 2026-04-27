# TenzoXAuthenticationCSharp

**TenzoXAuthenticationCSharp** is a simple C# library for adding **authentication and licensing** functionality to your applications. It provides **login, registration, license validation, and version checking** features in a few lines of code. Ideal for developers who want to secure their apps with minimal effort.

**Website:** [https://tenxoxauthentication.qzz.io](https://tenxoxauthentication.qzz.io)

## Features

* Login with username and password
* Registration with license keys
* Version checking to prevent outdated app usage
* Expiry date and user info retrieval
* Simple and clean C# integration

## Requirements

* .NET Framework / .NET Core
* **Newtonsoft.Json** (install via NuGet)

```bash
Install-Package Newtonsoft.Json
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/TenzoXAuthenticationCSharp.git
```

2. Include `txa.cs` in your project.
3. Ensure `Newtonsoft.Json` is installed in your project.

## Usage Example

```csharp
// auth info get from site
 public static TXA TXA = new TXA(
 name: "",
 secret: "",
 version: ""
        );


//call on program load
TXA.Init();

// Login
var result = await TXA.Login(textBox1.Text, textBox2.Text);

            if (result.Success)
            {
                label1.Text = result.Message;
            }
            else
            {
                label1.Text = result.Message;
            }


// Register
            var result = await TXA.Register(textBox1.Text, textBox2.Text, textBox3.Text);

            if (result.Success)
            {
                label1.Text = result.Message;
            }
            else
            {
                label1.Text = result.Message;
            }
//variable
            label1.Text = TXA.Var("AoB");

```






## Notes

* Ensure your app version matches the version expected by the library.
* License keys can be pre-generated or dynamically created by your system.
* Works with both **WinForms** and **console applications**.

## Credits

* Uses **Newtonsoft.Json** for JSON serialization and parsing


## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for bug fixes or new features.

## License

This project is licensed under the **TenzoXAuthenticationCSharp License** – see the [LICENSE](LICENSE) file for details.
