"""
Centralized logging configuration for ThreatSignal
"""

import logging
import sys
from datetime import datetime

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup centralized logging configuration"""
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Create logger
    logger = logging.getLogger("threatsignal")
    logger.setLevel(getattr(logging, level.upper()))
    logger.addHandler(console_handler)
    
    return logger

# Create default logger
logger = setup_logging()