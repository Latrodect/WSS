import os
import json
import re
import requests
from src.logger import Logger
from src.utils.animations import Spinner
import glob
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
        self.spinner = Spinner()
    
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
                try:
                    with open(file_path, 'r', encoding="utf-8") as file:
                        for line_number, line in enumerate(file, start=1):
                            for vulnerability_entry in vulnerabilities:
                                for vulnerability in vulnerability_entry["vulnerabilities"]:
                                    if vulnerability.lower() in line.lower():
                                        found_vulnerabilities.append(f"{vulnerability_entry['msg']} found in file '{file_path}' at line {line_number}")
                except UnicodeDecodeError:
                    with open(file_path, 'r', encoding="latin-1") as file:
                        for line_number, line in enumerate(file, start=1):
                            for vulnerability_entry in vulnerabilities:
                                for vulnerability in vulnerability_entry["vulnerabilities"]:
                                    if vulnerability.lower() in line.lower():
                                        found_vulnerabilities.append(f"{vulnerability_entry['msg']} found in file '{file_path}' at line {line_number}")

        return vulnerabilities

    def scan_xss(self, directory_path:str) -> list:
        """
        Scan a file for potential Cross-Site Scripting (XSS) vulnerabilities.

        Args:
            directory_path (str): The path to the file to be scanned.

        Returns:
            list: A list of potential XSS vulnerabilities found in the file.
        """
        xss_vulnerabilities = []
        xss_pattern = re.compile(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', re.IGNORECASE)

        try:
            for root, _, files in os.walk(directory_path):
                for file_name in files:
                    if file_name.endswith(('.html', '.htm', '.js')):
                        file_path = os.path.join(root, file_name)
                        with open(file_path, 'r', encoding='utf-8') as file:
                            content = file.read()
                            decoded_content = html.unescape(content)
                            if xss_pattern.search(decoded_content):
                                xss_vulnerabilities.append(f"Potential XSS vulnerability found in file '{file_path}'")
        except UnicodeDecodeError as e:
            self.logger.log_error(f"Error decoding file '{directory_path}': {e}")
        except FileNotFoundError:
            self.logger.log_error(f"File not found: '{directory_path}'")
        except Exception as e:
            self.logger.log_error(f"Error processing file '{directory_path}': {e}")

        return xss_vulnerabilities

    def scan_authentication_bypass_directory(self, directory_path):
        """
        Scan a directory for authentication bypass vulnerabilities.

        This method scans the specified directory and its subdirectories for authentication bypass vulnerabilities
        using predefined patterns. It searches for patterns in each line of each file within the directory and collects
        information about potential vulnerabilities.

        Args:
            directory_path (str): The path to the directory to be scanned.

        Returns:
            list: A list of dictionaries containing information about potential authentication bypass vulnerabilities.
                Each dictionary contains the following keys:
                - "file_path": The path to the file containing the vulnerability.
                - "line_number": The line number where the vulnerability was found.
                - "vulnerability": A description of the potential vulnerability.
        """
        vulnerabilities = []
        bypass_patterns = [
            r'password\s*=\s*"?\w+"?',             # Example: password="my_password"
            r'admin\s*=\s*"?\w+"?',                 # Example: admin="true"
            r'root\s*=\s*"?\w+"?',                  # Example: root="true"
            r'authenticated\s*=\s*"?\w+"?',         # Example: authenticated="false"
            r'role\s*=\s*"?\w+"?',                  # Example: role="admin"
            r'is_authenticated\s*=\s*\w+',         # Example: is_authenticated=True
            r'is_admin\s*=\s*\w+',                  # Example: is_admin=false
            r'is_superuser\s*=\s*\w+',              # Example: is_superuser=True
            r'auth\s*=\s*True|False',               # Example: auth=False
            r'has_permission\s*=\s*True|False',     # Example: has_permission=True
            r'authorized\s*=\s*True|False',         # Example: authorized=False
            r'is_logged_in\s*=\s*True|False',       # Example: is_logged_in=True
            r'is_valid_user\s*=\s*True|False',      # Example: is_valid_user=False
            r'is_administrator\s*=\s*True|False',   # Example: is_administrator=True
            r'is_authorized_user\s*=\s*True|False', # Example: is_authorized_user=False
            r'is_authenticated_user\s*=\s*True|False',  # Example: is_authenticated_user=True
            r'is_valid_login\s*=\s*True|False',     # Example: is_valid_login=False
            r'is_authorized_login\s*=\s*True|False',# Example: is_authorized_login=True
            r'can_access_admin_panel\s*=\s*True|False', # Example: can_access_admin_panel=False
            r'can_modify_settings\s*=\s*True|False',   # Example: can_modify_settings=True
            r'login_successful\s*=\s*True|False',     # Example: login_successful=False
            r'authenticated_user\s*=\s*True|False',   # Example: authenticated_user=True
            r'user_logged_in\s*=\s*True|False',       # Example: user_logged_in=False
            r'is_administrator\s*=\s*True|False',     # Example: is_administrator=True
            r'is_superadmin\s*=\s*True|False',        # Example: is_superadmin=False
            r'is_valid_session\s*=\s*True|False',     # Example: is_valid_session=True
            r'valid_token\s*=\s*True|False',          # Example: valid_token=False
            r'authenticated_session\s*=\s*True|False',# Example: authenticated_session=True
            r'is_valid_authentication\s*=\s*True|False',  # Example: is_valid_authentication=False
            r'is_authenticated_user\s*=\s*True|False',   # Example: is_authenticated_user=True
            r'is_logged_in_user\s*=\s*True|False',       # Example: is_logged_in_user=False
            r'is_authorized_admin\s*=\s*True|False',     # Example: is_authorized_admin=True
            r'can_access_secure_area\s*=\s*True|False',   # Example: can_access_secure_area=False
            r'is_valid_admin_login\s*=\s*True|False',    # Example: is_valid_admin_login=True
            r'is_admin_user\s*=\s*True|False',           # Example: is_admin_user=False
            r'is_user_authenticated\s*=\s*True|False',   # Example: is_user_authenticated=True
            r'is_valid_token\s*=\s*True|False',          # Example: is_valid_token=False
            r'valid_user_session\s*=\s*True|False',      # Example: valid_user_session=True
            r'admin_logged_in\s*=\s*True|False',         # Example: admin_logged_in=False
            r'is_admin_authenticated\s*=\s*True|False',  # Example: is_admin_authenticated=True
            r'is_session_valid\s*=\s*True|False',        # Example: is_session_valid=False
            r'authenticated_admin\s*=\s*True|False',     # Example: authenticated_admin=True
            r'user_authenticated\s*=\s*True|False',      # Example: user_authenticated=False
            r'is_valid_admin_session\s*=\s*True|False',  # Example: is_valid_admin_session=True
        ]

        try:
            self.logger.log_info(f"Scanning directory: {directory_path}")
            for root, _, files in os.walk(directory_path):
                for file_name in files:
                    if not file_name.endswith('.pyc'):  # Skip .pyc files
                        file_path = os.path.join(root, file_name)
                        vulnerabilities += self.scan_file_for_bypass(file_path, bypass_patterns)
        except Exception as e:
            self.logger.log_error(f"Error scanning directory {directory_path}: {str(e)}")

        return vulnerabilities

    def scan_file_for_bypass(self, file_path, bypass_patterns):
        """
        Scan a file for authentication bypass vulnerabilities using predefined patterns.

        Args:
            file_path (str): The path to the file to be scanned.
            bypass_patterns (list): A list of regular expressions representing authentication bypass patterns.

        Returns:
            list: A list of dictionaries containing information about potential authentication bypass vulnerabilities
                found in the file. Each dictionary contains the following keys:
                - "file_path": The path to the file containing the vulnerability.
                - "line_number": The line number where the vulnerability was found.
                - "vulnerability": A description of the potential vulnerability.
        """
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line_number, line in enumerate(file, start=1):
                    for pattern in bypass_patterns:
                        matches = re.findall(pattern, line)
                        for match in matches:
                            vulnerabilities.append({
                                "file_path": file_path,
                                "line_number": line_number,
                                "vulnerability": f"Potential authentication bypass: {match}"
                            })
        except Exception as e:
            self.logger.log_error(f"Error scanning file {file_path}: {str(e)}")

        return vulnerabilities
    
    @staticmethod
    def format_nvd_response(response):
        """
        Format the response from the National Vulnerability Database (NVD) into a list of dictionaries containing information about vulnerabilities.

        Args:
            response (str): The JSON response string from the NVD API.

        Returns:
            list: A list of dictionaries containing formatted information about vulnerabilities. Each dictionary contains the following keys:
                - 'CVE ID': The Common Vulnerabilities and Exposures (CVE) ID of the vulnerability.
                - 'Published Date': The date when the vulnerability was published.
                - 'Last Modified Date': The date when the vulnerability was last modified.
                - 'Description': The description of the vulnerability.
                    If no description is available, it defaults to 'N/A'.
        """
        formatted_results = []

        data = json.loads(response)

        vulnerabilities = data.get("vulnerabilities", [])

        for vulnerability in vulnerabilities:
            cve = vulnerability.get("cve", {})
            cve_id = cve.get("id", "N/A")
            published_date = cve.get("published", "N/A")
            last_modified_date = cve.get("lastModified", "N/A")
            
            descriptions = cve.get("descriptions", [])
            description = "N/A"
            for desc in descriptions:
                if 'value' in desc:
                    description = desc['value']
                    break

            formatted_results.append({
                "CVE ID": cve_id,
                "Published Date": published_date,
                "Last Modified Date": last_modified_date,
                "Description": description
            })

        return formatted_results

    def scan_package_vulnerabilities_nvd(self, package_name: str) -> list:
        """
        Check for known vulnerabilities in project dependencies using the National Vulnerability Database (NVD).

        Args:
            package_name (str): The name of the package to check for vulnerabilities.

        Returns:
            list: A list of dictionaries containing information about vulnerabilities.
        """
        vulnerabilities = []
        nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={package_name}"

        try:
            self.spinner.start()  
            response = requests.get(nvd_api_url)
            if response.status_code == 200:
                
                formatted_results = self.format_nvd_response(response.text)
                if formatted_results:
                    vulnerabilities.extend(formatted_results)
                else:
                    self.logger.log_info("No vulnerabilities found.")
            else:
                
                self.logger.log_error(f"Failed to fetch data from NVD API. Status code: {response.status_code}")

        except Exception as e:
            
            self.logger.log_error(f"An error occurred while fetching data from NVD API: {e}")
        finally:
            self.spinner.stop()  

        return vulnerabilities
    
    def check_sensitive_files_exposure(self, directory_path):
        """
        Check for sensitive files (e.g., configuration files, log files) in the specified directory.

        Args:
            directory_path (str): The path to the directory to be scanned.

        Returns:
            list: A list of sensitive files found.
        """
        sensitive_file_patterns = ['*.conf', '*.log', '*.key']
        sensitive_files = []

        for pattern in sensitive_file_patterns:
            sensitive_file_patterns.extend(glob.glob(os.path.join(directory_path, pattern)))
        return sensitive_files
    
    
    def detect_insecure_deserialization(self, directory_path):
        """
        Detect insecure deserialization vulnerabilities in the specified directory.

        Args:
            directory_path (str): Path to the directory to be scanned for insecure deserialization vulnerabilities.

        Returns:
            list: A list of insecure deserialization vulnerabilities found in the directory.
        """
        self.logger.log_info(f"Starting insecure deserialization detection for directory: {directory_path}")
        insecure_deserialization_vulnerabilities  = []

        for file_name in os.listdir(directory_path):
            file_path = os.path.join(directory_path, file_name)
            if self._is_insecure_deserialization(file_path):
                insecure_deserialization_vulnerabilities.append(file_path)
            
        if insecure_deserialization_vulnerabilities:
            self.logger.log_warning("Insecure deserialization vulnerabilities found:")
            for vulnerability in insecure_deserialization_vulnerabilities:
                self.logger.log_warning(f"- {vulnerability}")
        else:
            self.logger.log_info("No insecure deserialization vulnerabilities found.")
        
        return insecure_deserialization_vulnerabilities
    
    def _is_insecure_deserialization(self, file_path):
        """
        Check if a file contains indications of insecure deserialization.

        Args:
            file_path (str): Path to the file to be checked.

        Returns:
            bool: True if the file indicates insecure deserialization, False otherwise.
        """
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                if "serialize" in content and "unserialize" in content:
                    return True
        except Exception as e:
            self.logger.log_error(f"Error processing file {file_path}: {str(e)}")

        return False

    def detect_access_control_vulnerabilities(self, directory_path):
        """
        Detect access control vulnerabilities in the codebase.

        Args:
            directory_path (str): Path to the directory to be scanned for access control vulnerabilities.

        Returns:
            list: A list of file paths containing potential access control vulnerabilities.
        """
        access_control_vulnerabilities = []

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                if not file_name.endswith('.pyc'): 
                    file_path = os.path.join(root, file_name)
                    if self._has_access_control_vulnerabilities(file_path):
                        access_control_vulnerabilities.append(file_path)

        return access_control_vulnerabilities
    
    def _has_access_control_vulnerabilities(self, file_path):
        """
        Check if a file contains indications of access control vulnerabilities.

        Args:
            file_path (str): Path to the file to be checked.

        Returns:
            bool: True if the file contains indications of access control vulnerabilities, False otherwise.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            insecure_reference_pattern = re.compile(r'\b(admin_page|privileged_resource)\b')
            insecure_method_call_pattern = re.compile(r'\bcheck_permissions\(\s*\)\s*;\s*$')

            insecure_references = insecure_reference_pattern.findall(content)
            insecure_method_calls = insecure_method_call_pattern.findall(content)

            if insecure_references or insecure_method_calls:
                self.logger.log_warning(f"Access control vulnerability detected in file: {file_path}")
                if insecure_references:
                    self.logger.log_warning("Insecure references found:")
                    for reference in insecure_references:
                        self.logger.log_warning(f"- {reference}")
                if insecure_method_calls:
                    self.logger.log_warning("Insecure method calls found:")
                    for method_call in insecure_method_calls:
                        self.logger.log_warning(f"- {method_call}")
                return True  

        except Exception as e:
            self.logger.log_error(f"Error processing file {file_path}: {str(e)}")

        return False
    
    def detect_sql_injection(self, directory_path):
        """
        Detect SQL injection vulnerabilities in code files within a directory.

        Args:
            directory_path (str): The path to the directory to be scanned.

        Returns:
            list: A list of dictionaries containing information about potential SQL injection vulnerabilities.
                Each dictionary contains the following keys:
                - "file_path": The path to the file containing the vulnerability.
                - "line_number": The line number where the vulnerability was found.
                - "vulnerability": A description of the potential SQL injection vulnerability.
        """
        sql_injection_files = []

        sql_pattern = r'(\bselect\b|\bupdate\b|\bdelete\b|\binsert\b|\bdrop\b|\btruncate\b|\bunion\b|\bjoin\b|\bwhere\b|\bfrom\b|\border by\b|\bgroup by\b|\bexec\b|\bexecute\b|\bsp_executesql\b|\bdeclare\b|\bcreate\b|\balter\b|\bbackup\b|\brestore\b)'

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'r', encoding='utf-8') as file:
                    for line_number, line in enumerate(file, 1):
                        if re.search(sql_pattern, line, re.IGNORECASE):
                            sql_injection_files.append({
                                'file_path': file_path,
                                'line_number': line_number,
                                'vulnerability': 'Potential SQL injection detected'
                            })
                            break

        return sql_injection_files
