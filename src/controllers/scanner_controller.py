from models.scanner_model import LocalScanner
from serpant.logger import Logger

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
