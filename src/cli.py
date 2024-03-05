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
        jwt_token="123"
        banner = """

  ██████ ▓█████  ██▀███   ██▓███   ▄▄▄       ███▄    █ ▄▄▄█████▓
▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▓██░  ██▒▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒
░ ▓██▄   ▒███   ▓██ ░▄█ ▒▓██░ ██▓▒▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒   ██▒▒▓█  ▄ ▒██▀▀█▄  ▒██▄█▓▒ ▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██████▒▒░▒████▒░██▓ ▒██▒▒██▒ ░  ░ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   
░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░░▒ ░       ▒   ▒▒ ░░ ░░   ░ ▒░    ░    
░  ░  ░     ░     ░░   ░ ░░         ░   ▒      ░   ░ ░   ░      
      ░     ░  ░   ░                    ░  ░         ░          
                                                                

World Serpant Search is CLI Tools for Vulnerability Detection                                 
        """
        cprint(banner, "red")

    def run(self):
        """
        Runs the command-line interface.
        """
        parser = argparse.ArgumentParser(description="World Serpant Search CLI: Scan directories for vulnerabilities.")
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        lscan_parser = subparsers.add_parser("localscan", help="Scan a local directory for vulnerabilities")
        lscan_parser.add_argument('directory', help="Path to the directory to be scanned.")

        args = parser.parse_args()
        if args.command == "localscan":
            self.controller.scan_local_directory(args.directory)
        else:
            print("Invalid command. Use 'serpant -h' for help.")

def main():
    """
    Entry point of the CLI application. private_key
    """
    cli = CommandLineInterface()
    cli.run()

if __name__ == "__main__":
    main()