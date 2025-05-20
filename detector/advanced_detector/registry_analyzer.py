import winreg
import os
from logger_setup import logger
from utils import get_appdata_path

# Registry key for startup programs for the current user
RUN_KEY_PATH = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
SUSPICIOUS_VBS_PATTERN = ".vbs" 
POTENTIAL_MALWARE_COMMAND = "gup.exe" 

def scan_hkcu_run_key():
    """
    Scans the HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key
    for suspicious entries, particularly VBS scripts in APPDATA or commands launching GUP.exe.
    Returns a list of suspicious findings.
    """
    logger.info(f"Scanning registry key: HKEY_CURRENT_USER\\{RUN_KEY_PATH}")
    suspicious_entries = []
    appdata_path = get_appdata_path().lower() if get_appdata_path() else ""

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    i += 1
                    
                    is_suspicious = False
                    details = []

                    # Check 1: VBS file in command
                    if SUSPICIOUS_VBS_PATTERN in value_data.lower():
                        vbs_path_start = value_data.lower().find(SUSPICIOUS_VBS_PATTERN)
                        if vbs_path_start != -1:
                            potential_path = value_data[vbs_path_start - (len(value_data) - value_data.rfind(' ', 0, vbs_path_start)) if ' ' in value_data[:vbs_path_start] else 0:].split(' ')[0].strip('\"')
                            if os.path.exists(potential_path):
                                associated_file = potential_path

                        if appdata_path and appdata_path in value_data.lower():
                            is_suspicious = True
                            details.append(f"VBS script located in APPDATA: {value_data}")
                            logger.warning(f"Suspicious startup entry '{value_name}': VBS in APPDATA: {value_data}")

                        else: # VBS but not in APPDATA, still worth noting
                            is_suspicious = True
                            details.append(f"Contains VBS script: {value_data}")
                            logger.warning(f"Suspicious startup entry '{value_name}': VBS script: {value_data}")
                            


                    # Check 2: References POTENTIAL_MALWARE_COMMAND (e.g., gup.exe)
                    if POTENTIAL_MALWARE_COMMAND.lower() in value_data.lower():
                        is_suspicious = True
                        details.append(f"Launches '{POTENTIAL_MALWARE_COMMAND}'.")
                        logger.warning(f"Suspicious startup entry '{value_name}': references '{POTENTIAL_MALWARE_COMMAND}': {value_data}")
                    
                    # Check 3: Unusually long command strings or obfuscated commands (basic check)
                    if len(value_data) > 260: 
                        is_suspicious = True 
                        details.append(f"Command is unusually long (length: {len(value_data)}).")
                        logger.warning(f"Suspicious startup entry '{value_name}': very long command: {value_data[:100]}...")


                    if is_suspicious:
                        suspicious_entries.append({
                            "key_path": f"HKCU\\{RUN_KEY_PATH}",
                            "value_name": value_name,
                            "value_data": value_data,
                            "type": "Suspicious Startup Entry",
                            "details": details,
                            "associated_file": associated_file
                        })
                except OSError:
                    break
    except FileNotFoundError:
        logger.error(f"Registry key HKEY_CURRENT_USER\\{RUN_KEY_PATH} not found.")
    except Exception as e:
        logger.error(f"Error accessing registry key HKEY_CURRENT_USER\\{RUN_KEY_PATH}: {e}")

    if not suspicious_entries:
        logger.info(f"No suspicious entries found in HKCU\\{RUN_KEY_PATH} based on current criteria.")
    return suspicious_entries

def delete_registry_value(key_path, value_name):

    """

    Deletes a specific value from a registry key.

    key_path should be in the format 'HKCU\\Software\\...'

    """

    try:

        # Split the key_path into root and subkey

        root_key_str, subkey = key_path.split('\\', 1)

        

        # Map string root key to winreg constant

        if root_key_str == "HKCU":

            root_key = winreg.HKEY_CURRENT_USER

        elif root_key_str == "HKLM":

            root_key = winreg.HKEY_LOCAL_MACHINE

        else:

            logger.error(f"Unsupported root key: {root_key_str}")

            return False



        with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_SET_VALUE) as key:

            winreg.DeleteValue(key, value_name)

            logger.info(f"Successfully deleted registry value: {value_name} from {key_path}")

            return True

    except FileNotFoundError:

        logger.error(f"Registry key not found: {key_path}")

        return False

    except PermissionError:

        logger.error(f"Permission denied to delete registry value. Run as Administrator.")

        return False

    except Exception as e:

        logger.error(f"Error deleting registry value {value_name} from {key_path}: {e}")

        return False



def delete_file(file_path):
    """
    Deletes a specified file.
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Successfully deleted file: {file_path}")
            return True

        else:
            logger.warning(f"File not found, cannot delete: {file_path}")
            return False

    except PermissionError:
        logger.error(f"Permission denied to delete file: {file_path}. Run as Administrator.")
        return False

    except Exception as e:
        logger.error(f"Error deleting file {file_path}: {e}")
        return False