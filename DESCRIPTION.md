# World Serpant Search

![Alt Text](https://github.com/Latrodect/wss-repo-vulnerability-search-manager/raw/main/image/README/1709693527726.png)

World Serpant Search is a command-line tool for vulnerability detection. It allows you to scan directories for various types of vulnerabilities, including XSS vulnerabilities, authentication bypass vulnerabilities, and package vulnerabilities using the National Vulnerability Database (NVD).

![Flow Chart](https://github.com/Latrodect/wss-repo-vulnerability-search-manager/raw/main/image/README/1709722154357.png)

## Installation

To install World Serpant Search, you can use pip:

```bash
pip install serpant
```

## Usage and Examples

To use the CLI, follow the instructions below:

1. Install the CLI using pip:

   ```bash
   pip install serpant
   ```

2. Run the CLI using the following command:

   ```bash
   serpant
   ```

3. Use the available commands to perform vulnerability scans. For example:

   ```bash
   serpant scan /path/to/directory
   ```

4. For scan local repo:

   ```bash
   serpant scan /path/to/directory
   ```

5. For SQL injection detection:

   ```bash
   serpant sqlinjection /path/to/directory
   ```

6. For search authentication bypass in local repo:

   ```bash
   serpant abypass /path/to/directory
   ```

6. For detect xss vulnerabilities repo:

   ```bash
   serpant xss /path/to/directory
   ```

7. For search vulnerabilities in national vulnerability databae:

   ```bash
   serpant nvd package name
   ```

8. For check sensitive data exposure in local repo:

   ```bash
   serpant sensetive /path/to/directory
   ```

9. For check unsecure deserialization:

   ```bash
   serpant deserialization /path/to/directory
   ```

10. For detect access control vulnerabilities:

   ```bash
   serpant accesscontrol /path/to/directory
   ```

# Model Logic Explanation

## CommandLineInterface

The `CommandLineInterface` class represents the command-line interface for the CLI tool. It provides methods for initializing the CLI, printing the banner, and running the interface.

- `__new__(cls)`: This method ensures that only one instance of the `CommandLineInterface` class is created using the Singleton design pattern.
- `__init__(self)`: Initializes the command-line interface and prints the banner.
- `_print_banner(self)`: Prints the banner when the CLI initializes.
- `run(self)`: Runs the command-line interface by parsing arguments and executing corresponding commands.

## ScannerController

The `ScannerController` class is responsible for controlling scanning operations and interacting with the underlying data and business logic.

- `scan_local_directory(self, directory)`: Scans a local directory for vulnerabilities.
- `scan_xss_directory(self, directory)`: Scans a local directory for XSS vulnerabilities.
- `scan_authentication_bypass_directory(self, directory)`: Scans a directory for authentication bypass vulnerabilities.
- `scan_package_vulnerabilities_nvd(self, package)`: Checks package vulnerabilities using the National Vulnerability Database (NVD).
- `check_sensitive_files_exposure(self, directory)`: Checks for sensitive file exposure in a directory.
- `detect_insecure_deserialization(self, directory)`: Detects insecure deserialization vulnerabilities.
- `detect_access_control_vulnerabilities(self, directory)`: Detects access control vulnerabilities.

## Business Logic

### Local Repository Scan

Implement a feature to scan a local directory or project for common vulnerabilities such as exposed secrets, hardcoded credentials, or sensitive data.

### Remote Repository Scan

Extend the application to support scanning remote repositories by providing a URL. This could involve fetching the repository contents and analyzing them for vulnerabilities.

### SQL Injection Detection

Implement a feature to detect SQL injection vulnerabilities in code files or database configurations.

### Cross-Site Scripting (XSS) Detection

Develop functionality to detect cross-site scripting vulnerabilities in web applications or scripts.

### Sensitive Data Exposure Detection

Implement a feature to identify instances where sensitive data such as API keys, passwords, or personal information is exposed in the codebase.

### Dependency Vulnerability Check

Integrate with package vulnerability databases (e.g., NVD) to check for known vulnerabilities in project dependencies.

### Authentication Bypass Detection

Implement checks to identify potential authentication bypass vulnerabilities in the application.

### Insecure Deserialization Detection

Develop functionality to detect insecure deserialization vulnerabilities in the codebase.

### Sensitive File Exposure Check

Implement checks to identify sensitive files (e.g., configuration files, log files) that may be exposed to unauthorized access.

### Access Control Vulnerability Check

Develop checks to identify access control vulnerabilities, such as insecure direct object references or missing authorization checks.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
