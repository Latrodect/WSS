import argparse
from controllers.scanner_controller import ScannerController
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

  ██████ ▓█████  ██▀███   ██▓███   ▄▄▄       ███▄    █ ▄▄▄█████▓
▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▓██░  ██▒▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒
░ ▓██▄   ▒███   ▓██ ░▄█ ▒▓██░ ██▓▒▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒   ██▒▒▓█  ▄ ▒██▀▀█▄  ▒██▄█▓▒ ▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██████▒▒░▒████▒░██▓ ▒██▒▒██▒ ░  ░ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   
░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░░▒ ░       ▒   ▒▒ ░░ ░░   ░ ▒░    ░    
░  ░  ░     ░     ░░   ░ ░░         ░   ▒      ░   ░ ░   ░      
      ░     ░  ░   ░                    ░  ░         ░          
                                                                

                                         
        """
        cprint(banner, "red")

    def run(self):
        """
        Runs the command-line interface.
        """
        parser = argparse.ArgumentParser(description="Scan a local directory for vulnerabilities.")
        parser.add_argument('directory', help="Path to the directory to be scanned.")

        args = parser.parse_args()

        self.controller.scan_local_directory(args.directory)

def main():
    """
    Entry point of the CLI application.
    """
    cli = CommandLineInterface()
    cli.run()

if __name__ == "__main__":
    main()
