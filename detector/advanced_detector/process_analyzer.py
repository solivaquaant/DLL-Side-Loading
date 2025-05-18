# process_analyzer.py
import psutil
from logger_setup import logger

# Target process names from the scenario
TARGET_PARENT_PROCESS_NAME = "GUP.exe"
TARGET_CHILD_PROCESS_NAME = "svchost.exe" # Note: svchost.exe is a common system process. Context is key.

# Added: Standard parent processes for svchost.exe
STANDARD_SVCHOST_PARENTS = [
    "services.exe",
    "wininit.exe",
    "taskhostw.exe",
    "smss.exe",
    "csrss.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe", # explorer.exe can sometimes parent svchost, worth noting but less suspicious than others
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

def get_process_details(proc):
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

        # Loaded DLLs (can be numerous, might want to filter or summarize)
        try:
            details['dlls'] = [dll.path for dll in proc.memory_maps(grouped=False) if dll.path.lower().endswith(".dll")]
        except (psutil.AccessDenied, psutil.Error) as e: # Error can be raised on some systems/processes
            logger.debug(f"Could not retrieve DLLs for PID {proc.pid}: {e}")
            details['dlls'] = ["Access Denied or Error"]

        # Network connections
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


def analyze_all_processes():
    """
    Analyzes all running processes for the GUP.exe -> svchost.exe pattern.
    Returns a list of suspicious findings.
    """
    logger.info("Starting scan of all running processes for GUP.exe -> svchost.exe pattern.")
    suspicious_findings = []

    gup_processes = get_process_by_name(TARGET_PARENT_PROCESS_NAME)
    if not gup_processes:
        logger.info(f"No active '{TARGET_PARENT_PROCESS_NAME}' processes found.")

    for gup_proc in gup_processes:
        try:
            logger.info(f"Found '{TARGET_PARENT_PROCESS_NAME}' (PID: {gup_proc.pid}). Checking its children.")
            gup_details = get_process_details(gup_proc)
            if not gup_details: continue

            children = gup_proc.children(recursive=False) # Only direct children
            for child in children:
                try:
                    if child.name().lower() == TARGET_CHILD_PROCESS_NAME.lower():
                        logger.warning(
                            f"Suspicious: '{TARGET_PARENT_PROCESS_NAME}' (PID: {gup_proc.pid}) "
                            f"spawned '{TARGET_CHILD_PROCESS_NAME}' (PID: {child.pid})."
                        )
                        child_details = get_process_details(child)
                        finding = {
                            "type": "Suspicious Process Chain",
                            "gup_process": gup_details,
                            "svchost_process": child_details,
                            "message": f"'{TARGET_PARENT_PROCESS_NAME}' (PID {gup_proc.pid}) spawned "
                                       f"'{TARGET_CHILD_PROCESS_NAME}' (PID {child.pid}). "
                                       f"This is a strong indicator of the described attack.",
                            "action_taken": "alert" # Placeholder for now
                        }
                        suspicious_findings.append(finding)

                        # Further analysis of the suspicious svchost.exe
                        if child_details and child_details.get('connections'):
                            logger.info(f"Network connections for suspicious svchost.exe (PID {child.pid}): {child_details['connections']}")
                        if child_details and child_details.get('dlls'):
                             # Check for unusually loaded DLLs if any specific are known for the shellcode
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

# Added: Function to analyze svchost.exe parent processes
def analyze_svchost_parents():
    """
    Analyzes svchost.exe processes to see if they have non-standard parent processes.
    Returns a list of suspicious findings.
    """
    logger.info("Starting scan for svchost.exe with non-standard parents.")
    suspicious_findings = []

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
                        # Get more details for the suspicious svchost process
                        svchost_details = get_process_details(proc)
                        if svchost_details:
                             suspicious_findings.append({
                                 "type": "Suspicious svchost Parent",
                                 "svchost_process": svchost_details,
                                 "parent_process": {"pid": parent_pid, "name": parent_proc.name()},
                                 "message": f"svchost.exe (PID {proc.info['pid']}) has non-standard parent '{parent_proc.name()}' (PID {parent_pid}).",
                                 "action_taken": "alert" # Placeholder for now
                             })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                     # If parent process is gone or inaccessible, it might also be suspicious
                     logger.warning(
                         f"Suspicious: Cannot access parent of svchost.exe (PID: {proc.info['pid']}). "
                         f"Parent PID: {parent_pid} (possibly terminated or access denied)."\
                     )
                     svchost_details = get_process_details(proc) # Still get details of the svchost process itself if possible
                     if svchost_details:
                          suspicious_findings.append({
                              "type": "Suspicious svchost Parent (Parent Inaccessible)",
                              "svchost_process": svchost_details,
                              "parent_process": {"pid": parent_pid, "name": "Inaccessible or Terminated"},
                              "message": f"svchost.exe (PID {proc.info['pid']}) parent (PID {parent_pid}) is inaccessible or terminated.",
                              "action_taken": "alert" # Placeholder for now
                          })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that are gone or cannot be accessed during iteration
            continue

    if not suspicious_findings:
        logger.info("No svchost.exe processes with non-standard parents found.")

    return suspicious_findings


def scan_process_by_pid(pid_to_scan):
    """Scans a specific process by its PID."""
    logger.info(f"Scanning process with PID: {pid_to_scan}")
    proc = get_process_by_pid(pid_to_scan)
    if not proc:
        return None

    details = get_process_details(proc)
    if details:
        logger.info(f"Details for PID {pid_to_scan}: Name: {details['name']}, Parent: {details['parent_name']} (PID: {details['ppid']})")
        # You can add more specific checks here if needed
        # For example, if this PID is svchost.exe, check its parent.
        if details['name'].lower() == TARGET_CHILD_PROCESS_NAME.lower():
            if details['parent_name'].lower() == TARGET_PARENT_PROCESS_NAME.lower():
                logger.warning(f"PID {pid_to_scan} ({details['name']}) was spawned by {details['parent_name']} (PID {details['ppid']}). This matches the attack pattern!")
                details['suspicion_notes'] = f"Matches GUP.exe -> svchost.exe pattern."
            # Added: Check for unusual parent for svchost.exe in single PID scan
            elif details['parent_name'].lower() not in STANDARD_SVCHOST_PARENTS:
                 logger.warning(f"PID {pid_to_scan} ({details['name']}) has an unusual parent: {details['parent_name']} (PID {details['ppid']}). Legitimate svchost.exe instances are typically children of services.exe.")
                 details['suspicion_notes'] = f"Unusual parent for svchost.exe."


    return details

def list_all_process_dlls():
    """Lists all processes and their loaded DLLs (can be very verbose)."""
    logger.info("Listing all processes and their loaded DLLs. This might take a while and produce a lot of output.")
    all_proc_dlls = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            p_info = proc.as_dict(attrs=['pid', 'name'])
            p_instance = psutil.Process(p_info['pid'])
            dlls = []
            try:
                maps = p_instance.memory_maps(grouped=False)
                for mmap in maps:
                    if mmap.path and mmap.path.lower().endswith(".dll"):
                        dlls.append(mmap.path)
            except (psutil.AccessDenied, psutil.Error, psutil.NoSuchProcess): # Add NoSuchProcess
                dlls.append("Access Denied or Error retrieving DLLs")

            if dlls : # Only add if there are DLLs or an error message for DLLs
                 all_proc_dlls.append({"pid": p_info['pid'], "name": p_info['name'], "dlls": dlls})

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue # Skip processes that can't be accessed
    logger.info("Finished listing DLLs for all processes.")
    return all_proc_dlls
