from src.views.scanner_view import ScannerView
from src.models.scanner_model import LocalScanner
from src.logger import Logger

class ScannerController:
    """
    A class to control scanning operations.

    Attributes:
        logger (Logger): An instance of the Logger class for logging.
        scanner (LocalScanner): An instance of the LocalScanner class for scanning local directories.
    """

    def __init__(self) -> None:
        """
        Initializes the ScannerController object.
        """
        self.logger = Logger()
        self.scanner = LocalScanner()
        self.view = ScannerView()

    def scan_local_directory(self, directory_path: str) -> None:
        """
        Initiates a scan of a local directory for vulnerabilities.

        Args:
            directory_path (str): The path to the directory to be scanned.

        Returns:
            None
        """
        self.logger.log_info(f"Starting local directory scan: {directory_path}")
        vulnerabilities = self.scanner.scan_directory(directory_path)
        self.view.display_scan_results(vulnerabilities)

    def scan_xss_directory(self, directory_path: str) -> None:
        """
        Scan a directory for potential Cross-Site Scripting (XSS) vulnerabilities.

        This method initiates a scan for XSS vulnerabilities within the specified directory. It utilizes the LocalScanner
        instance to perform the scanning operation. If potential vulnerabilities are found, they are logged as warnings
        along with details of the files and lines where they occur. If no vulnerabilities are detected, an info log
        indicates that no potential XSS vulnerabilities were found.

        Args:
            directory_path (str): The path to the directory to be scanned for XSS vulnerabilities.
        """
        self.logger.log_info(f"Starting XSS scan in directory: {directory_path}")
        vulnerabilities = self.scanner.scan_xss(directory_path)
        self.view.display_xss_vulnerabilities(vulnerabilities)

    def scan_authentication_bypass_directory(self, directory_path: str) -> None:
        """
        Scan a directory for authentication bypass vulnerabilities.

        This method scans the specified directory for authentication bypass vulnerabilities using the authentication bypass scanner.
        It then displays the results of the scan using the view's display_scan_results method.

        Args:
            directory_path (str): The path to the directory to be scanned.

        Returns:
            None
        """
        self.logger.log_info(f"Starting Authenticaiton Bypass scan in directory: {directory_path}")
        vulnerabilities = self.scanner.scan_authentication_bypass_directory(directory_path)
        self.view.display_authentication_bypass_scan_results(vulnerabilities)

    def scan_package_vulnerabilities_nvd(self, package_name: str) -> None:
        """
        Check for known vulnerabilities in a package using the National Vulnerability Database (NVD).

        Args:
            package_name (str): The name of the package to check for vulnerabilities.

        Returns:
            None
        """
        self.logger.log_info(f"Starting package vulnerabilities control for: {package_name}")
        vulnerabilities = self.scanner.scan_package_vulnerabilities_nvd(package_name)
        self.view.display_package_vulnerabilities_nvd(vulnerabilities)

    def check_sensitive_files_exposure(self, directory_path):
        """
        Check for sensitive file exposure in the specified directory.

        Args:
            directory_path (str): The path to the directory to be scanned.
        """
        self.logger.log_info(f"Starting sensitive files exposure check for directory: {directory_path}")
        sensitive_files = self.scanner.check_sensitive_files_exposure(directory_path)
        self.view.display_sensitive_files_exposure(sensitive_files)

    def detect_insecure_deserialization(self, directory_path):
        """
        Detect insecure deserialization vulnerabilities in the codebase.

        Args:
            directory_path (str): Path to the directory to be scanned for insecure deserialization vulnerabilities.
        """
        self.logger.log_info(f"Starting insecure deserialization detection for directory: {directory_path}")
        insecure_deserialization_vulnerabilities = self.scanner.detect_insecure_deserialization(directory_path)
        self.view.display_insecure_deserialization_vulnerabilities(insecure_deserialization_vulnerabilities)

    def detect_access_control_vulnerabilities(self, directory_path):
        """
        Detect access control vulnerabilities in the codebase.

        Args:
            directory_path (str): Path to the directory to be scanned for access control vulnerabilities.

        Returns:
            list: A list of file paths containing potential access control vulnerabilities.
        """
        self.logger.log_info(f"Starting access control vulnerability detection for directory: {directory_path}")
        access_control_vulnerabilities = self.scanner.detect_access_control_vulnerabilities(directory_path)
        return access_control_vulnerabilities