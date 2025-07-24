import os
import logging
from datetime import datetime
from typing import Optional

def setup_logger(log_level: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    try:
        # Get log level from environment or default to INFO
        if log_level is None:
            log_level = os.getenv('LOG_LEVEL', 'INFO')
        
        # Create logs directory if it doesn't exist
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_dir = os.path.join(project_root, '0_Data', 'Logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'MalLoc_{timestamp}.log')
        
        # Remove any existing handlers from the root logger to avoid conflicts
        root_logger = logging.getLogger()
        if root_logger.hasHandlers():
            root_logger.handlers.clear()
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        # Create logger
        logger = logging.getLogger('MalLoc')
        logger.setLevel(getattr(logging, log_level.upper()))
        
        # Log successful setup
        logger.info(f"Logging initialized. Log file: {log_file}")
        
        return logger
        
    except Exception as e:
        # Fallback to basic console logging if file logging fails
        print(f"Failed to setup logging: {str(e)}")
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger('MalLoc')

class Logger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance
    
    def _initialize_logger(self):
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '0_Data', 'Logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Create a unique log file for each run
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"MalLoc_{timestamp}.log")
        
        # Configure logging
        self.logger = logging.getLogger('MalLoc2025')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatters and add them to the handlers
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(file_formatter)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def exception(self, message):
        self.logger.exception(message) 