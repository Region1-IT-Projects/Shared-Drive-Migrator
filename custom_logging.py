import logging
import tempfile
import sys

# Create a temporary file
log_file = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
log_path = log_file.name
log_file.close()  # Close so logger can write to it

# Configure logging
logger = logging.getLogger("shared_drive_migrator")
logger.setLevel(logging.DEBUG)

# Avoid duplicate handlers if this file is imported multiple times
if not logger.hasHandlers():
    file_handler = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def get_logger():
    return logger

def get_log_path():
    return log_path