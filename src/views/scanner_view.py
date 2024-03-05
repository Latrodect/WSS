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
    
    def display_authentication_bypass_scan_results(self, vulnerabilities: list) -> None:
        """
        Display the results of the authentication bypass scan.

        This method takes a list of vulnerabilities found during the authentication bypass scan and prints them to the console.

        Args:
            vulnerabilities (list): A list of strings representing the vulnerabilities found during the scan.

        Returns:
            None
        """
        if vulnerabilities:
            self.logger.log_warning("Potential authentication bypass vulnerabilities found:")
            for vulnerability in vulnerabilities:
                self.logger.log_warning("-" + vulnerability)
        else:
            self.logger.log_info("No potential authentication bypass vulnerabilities found.")