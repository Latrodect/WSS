import logging
import colorlog

class Logger:
    """
    A singleton class for logging messages.

    This class provides a singleton instance of a logger with setup for logging messages to the console.
    
    Attributes:
        _instance: Singleton instance of the Logger class.
        logger: Logger object from the logging module for logging messages.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Create a new instance of Logger if it doesn't already exist.

        Returns:
            Logger: Singleton instance of the Logger class.
        """
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls, *args, **kwargs)
            cls._instance._setup_logger()
        return cls._instance
    
    def _setup_logger(self):
        """
        Set up the logger with appropriate configurations.

        This method sets up the logger with a StreamHandler for logging messages to the console.
        """
        self.logger = colorlog.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(log_level)s - %(white)s%(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'purple',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={
                'message': {'INFO': 'white'}
            }
        )

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def log_info(self, message):
        """
        Log an informational message.

        Args:
            message (str): The message to be logged.
        """
        self.logger.info(message, extra={'log_level': 'INFO'})

    def log_warning(self, message):
        """
        Log a warning message.

        Args:
            message (str): The warning message to be logged.
        """
        self.logger.warning(message)

    def log_error(self, message):
        """
        Log an error message.

        Args:
            message (str): The error message to be logged.
        """
        self.logger.error(message)
