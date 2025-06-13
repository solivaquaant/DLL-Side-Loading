import logging
import os
from datetime import datetime
from colorama import init, Fore, Style

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, f"detection_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Custom Formatter to add colors
class ColoredFormatter(logging.Formatter):
    FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    
    # Define color mapping for different log levels
    LOG_COLORS = {
        logging.DEBUG: Style.DIM + Fore.WHITE,
        logging.INFO: Fore.CYAN, 
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Style.BRIGHT + Fore.RED,
    }

    def format(self, record):
        log_message = super().format(record)
        # Add color based on log level
        color_prefix = self.LOG_COLORS.get(record.levelno, Fore.WHITE)
        return f"{color_prefix}{log_message}{Style.RESET_ALL}"

def setup_logger():
    """
    Sets up the global logger
    """
    logger = logging.getLogger("MalwareDetector")
    logger.setLevel(logging.DEBUG) 

    # File handler - logs everything (DEBUG and above)
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    formatter_fh = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
    fh.setFormatter(formatter_fh)
    logger.addHandler(fh)

    # Console handler - logs INFO and above
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO) # Only show INFO and above in console for brevity
    # formatter_ch = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(ColoredFormatter(ColoredFormatter.FORMAT)) # Thay bằng dòng này
    logger.addHandler(ch)
    
    return logger

logger = setup_logger()
