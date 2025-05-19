import hashlib
import configparser
import os
from logger_setup import logger

CONFIG_FILE = "config.ini"

def get_file_hash(file_path, hash_algo="sha256"):
    """
    Calculates the hash of a file.
    Supported algorithms: md5, sha1, sha256.
    """
    hasher = hashlib.new(hash_algo)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192): 
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error hashing file {file_path}: {e}")
        return None

def load_config():
    """
    Loads configuration from config.ini.
    """
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"Configuration file {CONFIG_FILE} not found. Using default values or expecting API key via argument.")
        # Create a default config object if file doesn't exist
        config['VirusTotal'] = {'api_key': '', 'virustotal_malicious_threshold': '5', 'virustotal_api_delay': '15'}
        config['Settings'] = {'virustotal_malicious_threshold': '5', 'virustotal_api_delay': '15'}
        return config
        
    try:
        # Specify UTF-8 encoding when reading the config file
        config.read(CONFIG_FILE, encoding='utf-8') 
        if 'VirusTotal' not in config:
            config['VirusTotal'] = {}
        if 'Settings' not in config:
            config['Settings'] = {}
        
        # Ensure default values if keys are missing
        if 'api_key' not in config['VirusTotal']:
            config['VirusTotal']['api_key'] = ''
        if 'virustotal_malicious_threshold' not in config['Settings']:
            config['Settings']['virustotal_malicious_threshold'] = '5'
        if 'virustotal_api_delay' not in config['Settings']:
            config['Settings']['virustotal_api_delay'] = '15'
            
    except configparser.Error as e:
        logger.error(f"Error reading configuration file {CONFIG_FILE}: {e}")
        # Return a default config object on error
        config = configparser.ConfigParser()
        config['VirusTotal'] = {'api_key': '', 'virustotal_malicious_threshold': '5', 'virustotal_api_delay': '15'}
        config['Settings'] = {'virustotal_malicious_threshold': '5', 'virustotal_api_delay': '15'}
    return config

# Load configuration once when the module is imported
config = load_config()
VT_API_KEY = config.get('VirusTotal', 'api_key', fallback='')
VT_MALICIOUS_THRESHOLD = config.getint('Settings', 'virustotal_malicious_threshold', fallback=5)
VT_API_DELAY = config.getint('Settings', 'virustotal_api_delay', fallback=15)


def get_appdata_path():
    """Returns the APPDATA path."""
    return os.environ.get('APPDATA', '')

