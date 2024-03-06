from src.logger import Logger

class ScannerView:
    """
    A class to display scan results.

    Attributes:
        logger (Logger): An instance of the Logger class for logging.
    """

    def __init__(self) -> None:
        """
        Initializes the ScannerView object.
        """
        self.logger = Logger()

    def display_scan_results(self, vulnerabilities: list) -> None:
        """
        Displays the scan results.

        Args:
            vulnerabilities (list): A list of vulnerabilities found during the scan.

        Returns:
            None
        """
        if vulnerabilities:
            self.logger.log_warning("Vulnerabilities found:")
            for vulnerability in vulnerabilities:
                self.logger.log_warning("-" + vulnerability)
        else:
            self.logger.log_info("No vulnerabilities found.")

    def display_xss_vulnerabilities(self, vulnerabilities: list) -> None:
        """
        Display XSS vulnerabilities.

        Args:
            vulnerabilities (list): A list of XSS vulnerabilities.
        """
        if vulnerabilities:
            self.logger.log_warning("Potential XSS vulnerabilities found:")
            for vulnerability in vulnerabilities:
                self.logger.log_warning("-" + vulnerability)
        else:
            self.logger.log_info("No potential XSS vulnerabilities found.")
    
    def display_authentication_bypass_scan_results(self, vulnerabilities):
        """
        Display the results of the authentication bypass vulnerability scan.

        Args:
            vulnerabilities (list): A list of dictionaries containing information about potential authentication
                bypass vulnerabilities. Each dictionary contains the following keys:
                - "file_path": The path to the file containing the vulnerability.
                - "line_number": The line number where the vulnerability was found.
                - "vulnerability": A description of the potential vulnerability.
        """
        if vulnerabilities:
            self.logger.log_warning("Potential authentication bypass vulnerabilities found:")
            for vulnerability in vulnerabilities:
                file_path = vulnerability.get("file_path", "Unknown")
                line_number = vulnerability.get("line_number", "Unknown")
                vulnerability_description = vulnerability.get("vulnerability", "Unknown")
                message = f"File: {file_path}, Line: {line_number}, Description: {vulnerability_description}"
                self.logger.log_warning(message)
        else:
            self.logger.log_info("No authentication bypass vulnerabilities found.")

    def display_package_vulnerabilities_nvd(self, vulnerabilities: list) -> None:
        """
        Display information about package vulnerabilities fetched from the National Vulnerability Database (NVD).

        Args:
            vulnerabilities (list): A list of dictionaries containing information about vulnerabilities.

        Returns:
            None
        """
        if vulnerabilities:
            self.logger.log_warning("Potential vulnerabilities found:")
            for vulnerability in vulnerabilities:
                cve_id = vulnerability.get('CVE ID', 'N/A')
                description = vulnerability.get('Description', 'N/A')
                last_modified_date = vulnerability.get('Last Modified Date', 'N/A')
                self.logger.log_warning(f"CVE ID: {cve_id}, Description: {description}, Last Modified Date:{last_modified_date}")
        else:
            self.logger.log_info("No vulnerabilities found.")

    def display_sensitive_files_exposure(self, sensitive_files):
        """
        Display sensitive files exposed in the directory.

        Args:
            sensitive_files (list): A list of paths to sensitive files exposed in the directory.
        """
        if sensitive_files:
            print("Sensitive files exposed:")
            for file_path in sensitive_files:
                print(file_path)
        else:
            print("No sensitive files exposed.")

    def display_insecure_deserialization_vulnerabilities(self, insecure_deserialization_vulnerabilities):
        """
        Display insecure deserialization vulnerabilities detected in the codebase.

        Args:
            insecure_deserialization_vulnerabilities (list): A list of paths to files containing insecure deserialization vulnerabilities.
        """
        if insecure_deserialization_vulnerabilities:
            print("Insecure deserialization vulnerabilities found:")
            for file_path in insecure_deserialization_vulnerabilities:
                print(file_path)
        else:
            print("No insecure deserialization vulnerabilities found.")

    def display_sql_injection_results(self, vulnerabilities):
        """
        Display information about SQL injection vulnerabilities.

        Args:
            vulnerabilities (list): A list of file paths containing potential SQL injection vulnerabilities.

        Returns:
            None
        """
        if vulnerabilities:
            print("SQL injection vulnerabilities found:")
            for vulnerability in vulnerabilities:
                print(f"- {vulnerability}")
        else:
            print("No SQL injection vulnerabilities found.")