import argparse
from src.controllers.scanner_controller import ScannerController
from termcolor import cprint

class CommandLineInterface:
    """
    A command-line interface for scanning directories for vulnerabilities.

    Attributes:
        controller (ScannerController): An instance of the ScannerController class for controlling scanning operations.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.controller = ScannerController()
        return cls._instance

    def __init__(self):
        """
        Initializes the command-line interface.
        """
        self._print_banner()

    def _print_banner(self):
        """
        Prints the banner when the CLI initializes.
        """
        banner = """


    ___       ___       ___       ___       ___       ___       ___   
   /\  \     /\  \     /\  \     /\  \     /\  \     /\__\     /\  \  
  /::\  \   /::\  \   /::\  \   /::\  \   /::\  \   /:| _|_    \:\  \ 
 /\:\:\__\ /::\:\__\ /::\:\__\ /::\:\__\ /::\:\__\ /::|/\__\   /::\__\\
 \:\:\/__/ \:\:\/  / \;:::/  / \/\::/  / \/\::/  / \/|::/  /  /:/\/__/
  \::/  /   \:\/  /   |:\/__/     \/__/    /:/  /    |:/  /   \/__/   
   \/__/     \/__/     \|__|               \/__/     \/__/            

         
World Serpant Search is CLI Tools for Vulnerability Detection                                 
        """
        cprint(banner, "light_magenta")

    def run(self):
        """
        Runs the command-line interface.
        """
        parser = argparse.ArgumentParser(description="World Serpant Search CLI: Scan directories for vulnerabilities.")
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        lscan_parser = subparsers.add_parser("scan", help="Scan a local directory for vulnerabilities")
        lscan_parser.add_argument('directory', help="Path to the directory to be scanned.")

        xss_parser = subparsers.add_parser("xss", help="Scan a local directory for XSS vulnerabilities")
        xss_parser.add_argument('directory', help="Path to the directory to be scanned.")

        abypass_parser = subparsers.add_parser("abypass", help="Scan a directory for authentication bypass vulnerabilities")
        abypass_parser.add_argument('directory', help="Path to the directory to be scanned for authentication bypass vulnerabilities.")

        nvd_parser = subparsers.add_parser("nvd", help="Check package vulnerabilities using the National Vulnerability Database (NVD)")
        nvd_parser.add_argument('package', help="Name of the package to check for vulnerabilities.")

        sensitive_parser = subparsers.add_parser("sensitive", help="Check for sensitive file exposure in a directory")
        sensitive_parser.add_argument('directory', help="Path to the directory to be checked for sensitive file exposure.")

        deserialization_parser = subparsers.add_parser("deserialization", help="Detect insecure deserialization vulnerabilities")
        deserialization_parser.add_argument('directory', help="Path to the directory to be scanned for insecure deserialization vulnerabilities.")

        access_control_parser = subparsers.add_parser("accesscontrol", help="Detect access control vulnerabilities")
        access_control_parser.add_argument('directory', help="Path to the directory to be scanned for access control vulnerabilities.")

        sql_injection_parser = subparsers.add_parser("sqlinjection", help="Detect SQL injection vulnerabilities")
        sql_injection_parser.add_argument('directory', help="Path to the directory to be scanned for SQL injection vulnerabilities.")

        args = parser.parse_args()
        if args.command == "scan":
            self.controller.scan_local_directory(args.directory)
        elif args.command == "xss":
            self.controller.scan_xss_directory(args.directory)
        elif args.command == "abypass":
            self.controller.scan_authentication_bypass_directory(args.directory)
        elif args.command == "nvd":
            self.controller.scan_package_vulnerabilities_nvd(args.package)
        elif args.command == "sensitive":
            self.controller.check_sensitive_files_exposure(args.directory)
        elif args.command == "deserialization":
            self.controller.detect_insecure_deserialization(args.directory)
        elif args.command == "accesscontrol":
            self.controller.detect_access_control_vulnerabilities(args.directory)
        elif args.command == "sqlinjection":
            self.controller.detect_sql_injection(args.directory)
        else:
            print("Invalid command. Use 'serpant -h' for help.")

def main():
    """
    Entry point of the CLI application.
    """
    cli = CommandLineInterface()
    cli.run()

if __name__ == "__main__":
    main()
