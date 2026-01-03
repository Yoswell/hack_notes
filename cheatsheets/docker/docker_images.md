### PowerShell in Docker

**PowerShell** is a cross-platform task automation and configuration management framework from Microsoft, consisting of a command-line shell and scripting language. It provides a robust command-line interface for interacting with the operating system and managing system resources. Unlike traditional shells that primarily handle text, PowerShell works with .NET objects, which allows for more structured data manipulation and easier chaining of commands.

* **Architecture:** Cross-platform shell and scripting language based on .NET
* **Data Handling:** Works with .NET objects instead of plain text
* **Use Cases:** CTF challenges for scripting exploits, automating tasks, analyzing Windows-based systems
* **Docker Integration:** Running PowerShell in containers allows for isolated execution, testing scripts without affecting the host system, and leveraging .NET SDK for advanced scripting

-----

### Why Use PowerShell in Docker?

Understanding the benefits of running PowerShell in containerized environments.

#### Isolation and Security

```
Run scripts in a sandboxed environment
```

* **Why it's important:** Prevents scripts from affecting the host system and provides a secure testing environment.

#### Cross-Platform Compatibility

```
PowerShell Core runs on Linux, macOS, and Windows
```

* **Why it's important:** Consistent PowerShell experience across different operating systems.

#### .NET Integration

```
Access to .NET libraries for complex operations
```

* **Why it's important:** Leverage the full power of .NET framework for advanced scripting and automation.

#### Environment Consistency

```
Reproducible environment for testing and development
```

* **Why it's important:** Ensures scripts behave the same way across different systems and deployments.

-----

### Installation and Usage

Getting started with PowerShell in Docker containers.

#### Official .NET SDK Image

```bash
docker pull mcr.microsoft.com/dotnet/sdk:9.0
```

* **Why use this:** The Microsoft .NET SDK image includes PowerShell Core pre-installed.
* **Best practice:** Use specific version tags for reproducibility.

#### Start Interactive Container

```bash
docker run -it mcr.microsoft.com/dotnet/sdk:9.0 pwsh
```

* **When to use:** For interactive exploration, testing commands, or debugging scripts.
* **What happens:** Launches PowerShell inside the container with an interactive terminal.

#### Mount Local Script Directory

```bash
docker run -it -v $(pwd):/scripts mcr.microsoft.com/dotnet/sdk:9.0 pwsh -File /scripts/myscript.ps1
```

* **When to use:** To execute local PowerShell scripts inside the container.
* **Volume mounting:** Maps current directory to `/scripts` inside container.

#### Exiting the Container

```bash
exit
```

* **When to use:** To terminate the PowerShell session and stop the container.
* **Alternative:** Press `Ctrl+D` to exit the shell.

-----

### Example Commands

Practical PowerShell commands and scripts for containerized environments.

#### List Files and Directories

```powershell
Get-ChildItem
```

* **When to use:** To explore the container's filesystem.
* **Alternative:** Use `ls` alias for familiar syntax.

#### Display Text Output

```powershell
Write-Host "Hello, CTF!"
```

* **When to use:** For debugging, logging, or displaying messages in scripts.
* **Output:** Prints text to the console with default formatting.

#### Download Web Content

```powershell
[System.Net.WebClient]::new().DownloadString("http://example.com")
```

* **When to use:** To fetch web content or API responses.
* **Security note:** Be cautious when downloading from untrusted sources.

#### HTTP Requests with Invoke-WebRequest

```powershell
Invoke-WebRequest -Uri "http://example.com" -Method GET
```

* **When to use:** More advanced HTTP operations with better error handling.
* **Alias:** `iwr` for shorter syntax.

#### Get PowerShell Version

```powershell
$PSVersionTable.PSVersion
```

**When to use:** To verify PowerShell version and capabilities.
**Output:** Displays version information in Major.Minor.Build format.

#### Check Container Environment

```powershell
Get-ComputerInfo | Select-Object -Property OsName, OsVersion
```

* **When to use:** To examine the container's operating system details.
* **Note:** Some properties may differ from host system.

-----

### Security Considerations

Important security practices when using PowerShell in Docker.

#### Script Trust and Validation

```
Avoid running untrusted scripts in containers
```

* **Why it's critical:** Even in containers, malicious scripts can exploit vulnerabilities or consume resources.

#### Immutable File Systems

```bash
docker run --read-only -it mcr.microsoft.com/dotnet/sdk:9.0 pwsh
```

* **When to use:** For enhanced security when testing unknown scripts.
* **Benefit:** Prevents scripts from modifying the container filesystem.

#### Image Vulnerability Scanning

```
Scan images for vulnerabilities with tools like Trivy
```

* **When to use:** Before deploying or using images in production environments.
* **Tools:** Trivy, Docker Scout, or other container security scanners.

#### Resource Limitations

```bash
docker run --memory="512m" --cpus="1" -it mcr.microsoft.com/dotnet/sdk:9.0 pwsh
```

* **When to use:** To prevent resource exhaustion by scripts.
* **Parameters:** Set memory, CPU, and other resource limits.

-----

**Made with love by VIsh0k**