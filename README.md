# World Serpant Search

![1709693527726](image/README/1709693527726.png)

World Serpant Search is a CLI tool for vulnerability detection. It allows you to scan directories for various types of vulnerabilities, including XSS vulnerabilities, authentication bypass vulnerabilities, and package vulnerabilities using the National Vulnerability Database (NVD).

```mermaid
%%{init: {'theme': 'default', 'themeVariables': { 'backgroundColor': '#FFFFFF' }}}%%
flowchart TD;
    style A fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style B fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style C fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style D fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style E fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style F fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style G fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style H fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style I fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;
    style J fill:#FFFFFF, stroke:#9c27b0, stroke-width:1px, fill-opacity: 0.7, stroke-opacity: 1, stroke-dasharray: 0;


    A[CLI] -->|Scan directory| B[ScannerController]
    A -->|Scan XSS| B
    A -->|Scan Authentication Bypass| B
    A -->|Check NVD| B
    B --> C[ScannerModel]
    C --> D[LocalScanner]
    C --> E[NVDScanner]
    C --> F[XSSScanner]
    C --> G[AuthenticationBypassScanner]
    D --> H[ScannerLogger]
    D --> I[TriangleSpinner]
    H --> J[Logger]
    I --> J
```
## Installation

To install World Serpant Search, you can use pip:

```bash
pip install world-serpant-search
```

## Usage

After installation, you can run the CLI by executing the following command:

```bash
serpant
```

This will display the available commands and usage instructions.

### Commands

- `scan`: Scan a local directory for vulnerabilities.

  ```bash
  serpant scan <directory>
  ```
- `xss`: Scan a local directory for XSS vulnerabilities.

  ```bash
  serpant xss <directory>
  ```
- `abypass`: Scan a directory for authentication bypass vulnerabilities.

  ```bash
  serpant abypass <directory>
  ```
- `nvd`: Check package vulnerabilities using the National Vulnerability Database (NVD).

  ```bash
  serpant nvd <package>
  ```

## Examples

Scan a local directory for vulnerabilities:

```bash
serpant scan /path/to/directory
```

Scan a local directory for XSS vulnerabilities:

```bash
serpant xss /path/to/directory
```

Scan a directory for authentication bypass vulnerabilities:

```bash
serpant abypass /path/to/directory
```

Check package vulnerabilities using the National Vulnerability Database (NVD):

```bash
serpant nvd package-name
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
