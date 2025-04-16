import logging
from datetime import datetime

# Configure the logger
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

def log_event(message):
    logging.info(message)
