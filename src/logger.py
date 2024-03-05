import logging

class Logger:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            
            cls._instance = super(Logger, cls).__mew__(cls, *args, **kwargs)
            cls._instance._setup_logger()
        return cls._instance
    
    def _setup_logger(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        def log_info(self, message):
            self.logger.info(message)

        def log_warning(self, message):
            self.logger.warning(message)

        def log_error(self, message):
            self.logger.error(message)
        