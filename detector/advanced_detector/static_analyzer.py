# static_analyzer.py
import os
import time
import requests
from logger_setup import logger
from utils import get_file_hash, VT_API_KEY, VT_MALICIOUS_THRESHOLD, VT_API_DELAY
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("pefile library not found. Digital signature check will be basic.")

# Global variable to store VirusTotal API key, can be overridden by command line
VIRUSTOTAL_API_KEY = VT_API_KEY

def set_vt_api_key(api_key):
    """Allows overriding the API key from main.py."""
    global VIRUSTOTAL_API_KEY
    VIRUSTOTAL_API_KEY = api_key
    logger.info("VirusTotal API Key has been set/updated.")

def check_virustotal(file_path):
    """
    Checks a file's hash against VirusTotal.
    Returns a tuple: (status, positive_scans, total_scans)
    status can be "malicious", "suspicious", "clean", "not_found", "error", "api_limit"
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not provided. Skipping VirusTotal check.")
        return "api_key_missing", 0, 0

    file_hash = get_file_hash(file_path)
    if not file_hash:
        return "error_hashing", 0, 0

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    logger.info(f"Querying VirusTotal for file: {file_path} (hash: {file_hash})")
    
    try:
        response = requests.get(url, headers=headers)
        time.sleep(VT_API_DELAY) # Respect API rate limits

        if response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            positive_scans = last_analysis_stats.get("malicious", 0) + \
                             last_analysis_stats.get("suspicious", 0) # Consider suspicious as positive for our count
            total_scans = sum(last_analysis_stats.values()) # This is a simplification, VT gives more detailed breakdown

            logger.debug(f"VirusTotal response for {file_hash}: {last_analysis_stats}")

            if positive_scans >= VT_MALICIOUS_THRESHOLD:
                return "malicious", positive_scans, total_scans
            elif positive_scans > 0:
                return "suspicious", positive_scans, total_scans
            else:
                return "clean", positive_scans, total_scans
        elif response.status_code == 404:
            logger.info(f"File hash {file_hash} not found on VirusTotal.")
            return "not_found", 0, 0
        elif response.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded.")
            return "api_limit", 0, 0
        elif response.status_code == 401:
            logger.error("VirusTotal API key is invalid or unauthorized.")
            return "api_unauthorized",0,0
        else:
            logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
            return "error", 0, 0
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to VirusTotal: {e}")
        return "error_request", 0, 0

def check_digital_signature(file_path):
    """
    Checks if a PE file (EXE, DLL) has a digital signature.
    Returns True if a signature directory exists, False otherwise or if not a PE file/pefile not available.
    """
    if not PEFILE_AVAILABLE:
        logger.debug(f"pefile not available, cannot check signature for {file_path}")
        return None # Unknown status

    if not os.path.exists(file_path):
        logger.error(f"File not found for signature check: {file_path}")
        return False

    try:
        pe = pefile.PE(file_path, fast_load=True)
        # The security directory entry index in the data directory array
        security_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > security_dir_idx:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx]
            if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                logger.debug(f"Digital signature found in {file_path}")
                return True
            else:
                logger.debug(f"No digital signature data found in {file_path}")
                return False
        else:
            logger.debug(f"Not enough data directories in PE header for {file_path}")
            return False
            
    except pefile.PEFormatError:
        logger.debug(f"{file_path} is not a valid PE file or pefile could not parse it.")
        return None # Not a PE file or parse error
    except Exception as e:
        logger.error(f"Error checking digital signature for {file_path}: {e}")
        return False

def scan_file(file_path, use_virustotal=False):
    """
    Performs static analysis on a single file.
    Returns a dictionary with findings.
    """
    logger.info(f"Statically scanning file: {file_path}")
    findings = {
        "file_path": file_path,
        "hash_sha256": get_file_hash(file_path),
        "signature_present": None,
        "virustotal_status": "not_checked",
        "virustotal_positives": 0,
        "virustotal_total": 0,
        "is_suspicious": False,
        "details": []
    }

    # Check signature for PE files
    if file_path.lower().endswith((".exe", ".dll", ".sys")):
        findings["signature_present"] = check_digital_signature(file_path)
        if findings["signature_present"] is False: # Explicitly False means unsigned
            findings["is_suspicious"] = True
            findings["details"].append("File is not digitally signed.")
            logger.warning(f"File {file_path} is not digitally signed.")
        elif findings["signature_present"] is True:
             logger.info(f"File {file_path} has a digital signature.")


    # Check with VirusTotal if enabled
    if use_virustotal:
        vt_status, vt_pos, vt_total = check_virustotal(file_path)
        findings["virustotal_status"] = vt_status
        findings["virustotal_positives"] = vt_pos
        findings["virustotal_total"] = vt_total
        if vt_status == "malicious":
            findings["is_suspicious"] = True
            findings["details"].append(f"VirusTotal: MALICIOUS ({vt_pos}/{vt_total})")
            logger.critical(f"MALICIOUS file detected by VirusTotal: {file_path} ({vt_pos}/{vt_total})")
        elif vt_status == "suspicious":
            findings["is_suspicious"] = True # Keep it suspicious even if below threshold for warning
            findings["details"].append(f"VirusTotal: SUSPICIOUS ({vt_pos}/{vt_total})")
            logger.warning(f"SUSPICIOUS file detected by VirusTotal: {file_path} ({vt_pos}/{vt_total})")
        elif vt_status in ["api_key_missing", "error_hashing", "api_limit", "error", "error_request", "api_unauthorized"]:
             findings["details"].append(f"VirusTotal check issue: {vt_status}")
        elif vt_status == "clean":
            findings["details"].append(f"VirusTotal: CLEAN ({vt_pos}/{vt_total})")
            logger.info(f"File {file_path} reported as CLEAN by VirusTotal.")
        elif vt_status == "not_found":
            findings["details"].append(f"VirusTotal: Not found.")
            logger.info(f"File {file_path} not found on VirusTotal.")


    # Specific check for VBS files as per scenario
    if file_path.lower().endswith(".vbs"):
        try:
            with open(file_path, "r", encoding='utf-8', errors='ignore') as f_vbs:
                content = f_vbs.read().lower()
                if "gup.exe" in content and "createobject(\"wscript.shell\").run" in content: # Basic check
                    findings["is_suspicious"] = True
                    findings["details"].append("VBS file potentially launches GUP.exe in background.")
                    logger.warning(f"Suspicious VBS file found: {file_path} - may launch GUP.exe")
        except Exception as e:
            logger.error(f"Could not read VBS file {file_path}: {e}")
            findings["details"].append(f"Error reading VBS file: {e}")
            
    return findings

def scan_folder(folder_path, use_virustotal=False):
    """
    Scans all relevant files in a given folder.
    Relevant files: .exe, .dll, .vbs, .sys (can be expanded)
    """
    logger.info(f"Starting static scan of folder: {folder_path}")
    all_findings = []
    allowed_extensions = (".exe", ".dll", ".vbs", ".sys", ".com", ".scr") # Add more if needed

    if not os.path.isdir(folder_path):
        logger.error(f"Folder not found: {folder_path}")
        return [{"error": f"Folder not found: {folder_path}"}]

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if file_name.lower().endswith(allowed_extensions):
                file_path = os.path.join(root, file_name)
                try:
                    file_findings = scan_file(file_path, use_virustotal)
                    if file_findings["is_suspicious"] or use_virustotal : # Report if suspicious or if VT was used (even for clean)
                        all_findings.append(file_findings)
                except Exception as e:
                    logger.error(f"Error scanning file {file_path}: {e}")
                    all_findings.append({
                        "file_path": file_path,
                        "error": str(e),
                        "is_suspicious": True,
                        "details": [f"Critical error during scan: {e}"]
                    })
    
    if not all_findings:
        logger.info(f"No suspicious files found in {folder_path} with current criteria.")
    return all_findings
