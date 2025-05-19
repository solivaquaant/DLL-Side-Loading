import winreg
import os
from logger_setup import logger
from utils import get_appdata_path

# Registry key for startup programs for the current user
RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
SUSPICIOUS_VBS_PATTERN = ".vbs" 
POTENTIAL_MALWARE_COMMAND = "gup.exe" 

def scan_hkcu_run_key():
    """
    Scans the HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run registry key
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
                        details.append(f"Contains '{SUSPICIOUS_VBS_PATTERN}'.")
                        # Check 2: If VBS, is it in APPDATA (common for malware persistence)?
                        if appdata_path and appdata_path in value_data.lower():
                            is_suspicious = True
                            details.append(f"VBS script located in APPDATA: {value_data}")
                            logger.warning(f"Suspicious startup entry '{value_name}': VBS in APPDATA: {value_data}")
                        else: # VBS but not in APPDATA, still worth noting
                            logger.info(f"Startup entry '{value_name}' contains VBS: {value_data}")


                    # Check 3: Command directly invokes GUP.exe (or similar patterns)
                    if POTENTIAL_MALWARE_COMMAND in value_data.lower():
                        is_suspicious = True
                        details.append(f"Command potentially launches '{POTENTIAL_MALWARE_COMMAND}'.")
                        logger.warning(f"Suspicious startup entry '{value_name}': references '{POTENTIAL_MALWARE_COMMAND}': {value_data}")
                    
                    # Check 4: Unusually long command strings or obfuscated commands (basic check)
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
                            "details": details
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