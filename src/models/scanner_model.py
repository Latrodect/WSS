import os
import json
from logger import Logger

class LocalScanner:
    """
    A class to perform local directory scanning for vulnerabilities.

    Attributes:
        logger (Logger): An instance of the Logger class for logging.
    """

    def __init__(self) -> None:
        """
        Initializes the LocalScanner object.
        """
        self.logger = Logger()

    def _load_vulnerabilities(self, custom_json_file=None) -> list:
        """
        Loads vulnerability patterns from a JSON file.

        Args:
            custom_json_file (str, optional): Path to a custom JSON file containing vulnerability patterns.

        Returns:
            list: A list of dictionaries containing vulnerability patterns.
        """
        default_json_path = os.path.join(os.path.dirname(__file__), "vulnerabilities.json")
        json_file = custom_json_file or default_json_path

        with open(json_file, 'r') as file:
            return json.load(file)

    def scan_directory(self, directory_path: str) -> None:
        """
        Scans a directory for vulnerabilities.

        Args:
            directory_path (str): The path to the directory to be scanned.
        """
        self.logger.log_info(f"Scanning directory: {directory_path}")
        found_vulnerabilities = []

        vulnerabilities = self._load_vulnerabilities()

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'r', encoding="utf-8") as file:
                    for line_number, line in enumerate(file, start=1):
                        for vulnerability in vulnerabilities:
                            if vulnerability["vulnerabilities"].lower() in line.lower():
                                found_vulnerabilities.append(f"{vulnerability['msg']} found in file '{file_path}' at line {line_number}")

        if found_vulnerabilities:
            self.logger.log_warning("Vulnerabilities found:")
            for vulnerability in found_vulnerabilities:
                self.logger.log_warning("-" + vulnerability)
        else:
            self.logger.log_info("No vulnerabilities found.")