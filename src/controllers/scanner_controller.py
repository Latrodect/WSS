import re
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
        if vulnerabilities:
            self.logger.log_warning("Vulnerabilities found during local scan.")
        else:
            self.logger.log_info("No vulnerabilities found in the local directory.")

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
        if vulnerabilities:
            self.logger.log_warning("Potential XSS vulnerabilities found:")
            self.view.display_scan_results(vulnerabilities)
        else:
            self.logger.log_info("No potential XSS vulnerabilities found.")