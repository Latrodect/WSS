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
