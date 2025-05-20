import psutil
import time
from logger_setup import logger
import static_analyzer

# Target process names from the scenario
TARGET_PARENT_PROCESS_NAME = "GUP.exe"
TARGET_CHILD_PROCESS_NAME = "svchost.exe" 

# Standard parent processes for svchost.exe
STANDARD_SVCHOST_PARENTS = [
    "services.exe",
    "wininit.exe",
    "taskhostw.exe",
    "smss.exe",
    "csrss.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
]


def get_process_by_name(process_name):
    """Finds processes by name."""
    processes_found = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid']):
        try:
            if proc.info['name'].lower() == process_name.lower():
                processes_found.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes_found

def get_process_by_pid(pid):
    """Gets a process by its PID."""
    try:
        return psutil.Process(pid)
    except psutil.NoSuchProcess:
        logger.warning(f"Process with PID {pid} not found.")
        return None

# Gather detailed information of a process
def get_process_details(proc, use_virustotal=False):
    """Gathers detailed information about a process."""
    details = {}
    try:
        details['pid'] = proc.pid
        details['name'] = proc.name()
        details['ppid'] = proc.ppid()
        parent_proc = psutil.Process(proc.ppid())
        details['parent_name'] = parent_proc.name()
        details['exe'] = proc.exe()
        details['cmdline'] = proc.cmdline()
        details['create_time'] = proc.create_time()
        details['status'] = proc.status()
        details['username'] = proc.username()

        # Retrieve the list of DLLs used by the process and perform VT check
        dll_list = [] 
        dll_vt_results = {} 
        try:
            maps = proc.memory_maps(grouped=False)
            for mmap in maps:
                if mmap.path and mmap.path.lower().endswith(".dll"):
                    dll_path = mmap.path
                    dll_list.append(dll_path)
                    #  VirusTotal check for DLLs
                    if use_virustotal:
                         vt_status, vt_pos, vt_total = static_analyzer.check_virustotal(dll_path)
                         dll_vt_results[dll_path] = {"status": vt_status, "positives": vt_pos, "total": vt_total}
                        #   logging for VT check on DLLs
                         if vt_status == "malicious":
                              logger.critical(f"Malicious DLL found in PID {proc.pid} ({proc.name()}): {dll_path} (VT: {vt_pos}/{vt_total})")
                         elif vt_status == "suspicious":
                              logger.warning(f"Suspicious DLL found in PID {proc.pid} ({proc.name()}): {dll_path} (VT: {vt_pos}/{vt_total})")
                         elif vt_status in ["api_key_missing", "error_hashing", "api_limit", "error", "error_request", "api_unauthorized"]:
                              logger.error(f"VirusTotal check failed for DLL {dll_path} in PID {proc.pid}: {vt_status}")
                         else:
                              logger.info(f"DLL {dll_path} in PID {proc.pid} is CLEAN according to VT ({vt_pos}/{vt_total})")

        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Could not retrieve DLLs for PID {proc.pid}: {e}")
            dll_list = ["Access Denied or Error"] # Keep this for basic info
            if use_virustotal: 
                dll_vt_results["Access Denied or Error"] = {"status": "not_checked", "positives": 0, "total": 0} 

        details['dlls'] = dll_list # Updated
        details['dll_virustotal'] = dll_vt_results 

        # Retrieve the network connections of the process
        try:
            connections = []
            for conn in proc.connections(kind='inet'):
                 connections.append({
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "laddr": conn.laddr,
                    "raddr": conn.raddr,
                    "status": conn.status
                 })
            details['connections'] = connections
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Could not retrieve network connections for PID {proc.pid}: {e}")
            details['connections'] = ["Access Denied or Error"]

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.error(f"Error getting details for process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
        return None
    return details


def analyze_all_processes(use_virustotal=False):
    """
    Analyzes all running processes for the GUP.exe -> svchost.exe pattern.
    Returns a list of suspicious findings.
    """
    logger.info("Starting scan of all running processes for GUP.exe -> svchost.exe pattern.")
    suspicious_findings = []

    time.sleep(10)

    gup_processes = get_process_by_name(TARGET_PARENT_PROCESS_NAME)
    if not gup_processes:
        logger.info(f"No active '{TARGET_PARENT_PROCESS_NAME}' processes found.")
        return suspicious_findings

    for gup_proc in gup_processes:
        try:
            logger.info(f"Found '{TARGET_PARENT_PROCESS_NAME}' (PID: {gup_proc.pid}). Checking its children.")
            gup_details = get_process_details(gup_proc, use_virustotal)
            if not gup_details: continue

            children = gup_proc.children(recursive=False)
            for child in children:
                try:
                    if child.name().lower() == TARGET_CHILD_PROCESS_NAME.lower():
                        logger.warning(
                            f"Suspicious: '{TARGET_PARENT_PROCESS_NAME}' (PID: {gup_proc.pid}) "
                            f"spawned '{TARGET_CHILD_PROCESS_NAME}' (PID: {child.pid})."
                        )
                        child_details = get_process_details(child, use_virustotal)
                        finding = {
                            "type": "Suspicious Process Chain",
                            "gup_process": gup_details,
                            "svchost_process": child_details,
                            "message": f"'{TARGET_PARENT_PROCESS_NAME}' (PID {gup_proc.pid}) spawned "
                                       f"'{TARGET_CHILD_PROCESS_NAME}' (PID {child.pid}). "
                                       f"This is a strong indicator of the described attack.",
                            "action_taken": "alert" 
                        }
                        suspicious_findings.append(finding)

                        if child_details and child_details.get('connections'):
                            logger.info(f"Network connections for suspicious svchost.exe (PID {child.pid}): {child_details['connections']}")
                        if child_details and child_details.get('dlls'):
                            logger.debug(f"DLLs for suspicious svchost.exe (PID {child.pid}): {child_details['dlls']}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    logger.debug(f"Could not access child process of GUP.exe (PID: {gup_proc.pid}).")
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug(f"GUP.exe process (PID: {gup_proc.pid}) disappeared or access denied during scan.")
            continue

    if not suspicious_findings:
        logger.info("No GUP.exe -> svchost.exe suspicious process chains found.")

    return suspicious_findings

def analyze_svchost_parents(use_virustotal=False):
    """
    Analyzes svchost.exe processes to see if they have non-standard parent processes.
    Returns a list of suspicious findings.
    """
    logger.info("Starting scan for svchost.exe with non-standard parents.")
    suspicious_findings = []

    time.sleep(10)

    # Check if svchost.exe processes exist after waiting.  basic check
    svchost_processes_check = get_process_by_name("svchost.exe") 
    if not svchost_processes_check: 
        logger.info("No svchost.exe processes found after waiting.") 
        return suspicious_findings 

    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            if proc.info['name'].lower() == "svchost.exe":
                parent_pid = proc.info['ppid']
                try:
                    parent_proc = psutil.Process(parent_pid)
                    parent_name = parent_proc.name().lower()

                    if parent_name not in STANDARD_SVCHOST_PARENTS:
                        logger.warning(
                            f"Suspicious svchost.exe (PID: {proc.info['pid']}) "
                            f"spawned by non-standard parent '{parent_proc.name()}' (PID: {parent_pid})."
                        )
                        svchost_details = get_process_details(proc, use_virustotal)
                        if svchost_details:
                             suspicious_findings.append({
                                "type": "Suspicious svchost Parent",
                                "svchost_process": svchost_details,
                                "parent_process": {"pid": parent_pid, "name": parent_proc.name()},
                                "message": f"svchost.exe (PID {proc.info['pid']}) has non-standard parent '{parent_proc.name()}' (PID {parent_pid}).",
                                "action_taken": "alert" 
                             })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    logger.warning(
                    f"Suspicious: Cannot access parent of svchost.exe (PID: {proc.info['pid']}). "
                    f"Parent PID: {parent_pid} (possibly terminated or access denied)."\
                    )
                    svchost_details = get_process_details(proc, use_virustotal) 
                    if svchost_details:
                        suspicious_findings.append({
                            "type": "Suspicious svchost Parent (Parent Inaccessible)",
                            "svchost_process": svchost_details,
                            "parent_process": {"pid": parent_pid, "name": "Inaccessible or Terminated"},
                            "message": f"svchost.exe (PID {proc.info['pid']}) parent (PID {parent_pid}) is inaccessible or terminated.",
                            "action_taken": "alert" 
                        })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not suspicious_findings:
        logger.info("No svchost.exe processes with non-standard parents found.")

    return suspicious_findings


def scan_process_by_pid(pid_to_scan, use_virustotal=False):
    """Scans a specific process by its PID."""
    logger.info(f"Scanning process with PID: {pid_to_scan}")
    proc = get_process_by_pid(pid_to_scan)
    if not proc:
        return None

    details = get_process_details(proc, use_virustotal)
    if details:
        logger.info(f"Details for PID {pid_to_scan}: Name: {details['name']}, Parent: {details['parent_name']} (PID: {details['ppid']})")

        if details['name'].lower() == TARGET_CHILD_PROCESS_NAME.lower():
            if details['parent_name'].lower() == TARGET_PARENT_PROCESS_NAME.lower():
                logger.warning(f"PID {pid_to_scan} ({details['name']}) was spawned by {details['parent_name']} (PID {details['ppid']}). This matches the attack pattern!")
                details['suspicion_notes'] = f"Matches GUP.exe -> svchost.exe pattern."
            elif details['parent_name'].lower() not in STANDARD_SVCHOST_PARENTS:
                 logger.warning(f"PID {pid_to_scan} ({details['name']}) has an unusual parent: {details['parent_name']} (PID {details['ppid']}). Legitimate svchost.exe instances are typically children of services.exe.")
                 details['suspicion_notes'] = f"Unusual parent for svchost.exe."

    return details

#  function scan_process_by_name
def scan_process_by_name(process_name, use_virustotal=False):
    """
    Finds processes by name and scans them, including optional VirusTotal checks for DLLs. 
    Includes a wait period. 
    Returns a list of process details.
    """
    logger.info(f"Starting scan for processes named: {process_name}")
    found_processes = []
    process_details_list = []  # to store details for found processes

    time.sleep(10)  # wait for processes to appear

    processes = get_process_by_name(process_name)
    if not processes:
        logger.info(f"No processes named '{process_name}' found after waiting.")
        return process_details_list

    logger.info(f"Found {len(processes)} process(es) named '{process_name}'. Analyzing details.")
    for proc in processes:
        try:
            #  use_virustotal to get_process_details call
            details = get_process_details(proc, use_virustotal)
            if details:
                process_details_list.append({"type": "ProcessDetails", **details})
                # Check for suspicious patterns if it's svchost.exe and not the target chain
                if details['name'].lower() == TARGET_CHILD_PROCESS_NAME.lower() and details.get('parent_name', '').lower() != TARGET_PARENT_PROCESS_NAME.lower():
                    if details.get('parent_name', '').lower() not in STANDARD_SVCHOST_PARENTS:
                        logger.warning(f"Suspicious svchost.exe (PID: {details['pid']}) found via name scan, spawned by non-standard parent '{details.get('parent_name','N/A')}' (PID: {details['ppid']}).")
                        details['suspicion_notes'] = (details.get('suspicion_notes', '') + " Unusual parent found via name scan.").strip()


        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            logger.debug(f"Process (PID potentially {proc.pid if hasattr(proc, 'pid') else 'unknown'}) disappeared or access denied during name scan.")
            continue
        except Exception as e:
            logger.error(f"An unexpected error occurred while analyzing process by name: {e}")

    return process_details_list

#  use_virustotal parameter
def list_all_process_dlls(use_virustotal=False):
    """
    Lists all processes and their loaded DLLs, including optional VirusTotal checks. 
    Can be very verbose. Includes a wait period. 
    """
    logger.info("Listing all processes and their loaded DLLs. This might take a while and produce a lot of output.")
    all_proc_dlls = []

    time.sleep(10)  # wait for processes to appear

    processes = list(psutil.process_iter(['pid', 'name'])) # Get a list to check if any exist 
    if not processes: 
        logger.info("No processes found after waiting to list DLLs.") 
        return all_proc_dlls

    for proc in processes: # Iterating over the list
        try:
            p_info = proc.as_dict(attrs=['pid', 'name'])
            pid = p_info['pid']
            name = p_info['name']  
            p_instance = psutil.Process(pid) # Use pid

            dll_list = [] 
            dll_vt_results = {} 

            try:
                maps = p_instance.memory_maps(grouped=False)
                for mmap in maps:
                    if mmap.path and mmap.path.lower().endswith(".dll"):
                        dll_path = mmap.path
                        dll_list.append(dll_path)
                        if use_virustotal:
                            vt_status, vt_pos, vt_total = static_analyzer.check_virustotal(dll_path)
                            dll_vt_results[dll_path] = {"status": vt_status, "positives": vt_pos, "total": vt_total}
                            #  logging for VT check on DLLs
                            if vt_status == "malicious":
                                logger.critical(f"Malicious DLL found in PID {pid} ({name}): {dll_path} (VT: {vt_pos}/{vt_total})")
                            elif vt_status == "suspicious":
                                logger.warning(f"Suspicious DLL found in PID {pid} ({name}): {dll_path} (VT: {vt_pos}/{vt_total})")
                            elif vt_status in ["api_key_missing", "error_hashing", "api_limit", "error", "error_request", "api_unauthorized"]:
                                logger.error(f"VirusTotal check failed for DLL {dll_path} in PID {pid}: {vt_status}")
                            else:
                                logger.info(f"DLL {dll_path} in PID {pid} is CLEAN according to VT ({vt_pos}/{vt_total})")

            except (psutil.AccessDenied, psutil.Error, psutil.NoSuchProcess):
                dll_list = ["Access Denied or Error retrieving DLLs"]
                if use_virustotal: 
                    dll_vt_results["Access Denied or Error"] = {"status": "not_checked", "positives": 0, "total": 0} 


            if dll_list : # Changed from if dlls:
                # Updated append to include VT results
                all_proc_dlls.append({"pid": pid, "name": name, "dlls": dll_list, "dll_virustotal": dll_vt_results})

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e: 
            logger.error(f"An unexpected error occurred while listing DLLs for PID {proc.pid}: {e}") 

    logger.info("Finished listing DLLs for all processes.")
    return all_proc_dlls