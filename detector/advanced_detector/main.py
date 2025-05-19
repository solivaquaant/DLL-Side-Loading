import argparse
import sys
import os
import time 
import static_analyzer
import process_analyzer
import registry_analyzer
import utils
import psutil
import tkinter as tk 

from datetime import datetime
from logger_setup import logger, LOG_FILE
from colorama import init, Fore, Style
from tkinter import messagebox 

init(autoreset=True)

# Alert the user with a message of varying severity levels (INFO, WARNING, CRITICAL)
def alert_user(message, severity="INFO"):
    """Prints a color-coded alert to the console and logs."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_prefix = f"ALERT [{severity}]"

    if severity == "CRITICAL":
        print(f"{Fore.RED}{Style.BRIGHT}{timestamp} - {log_prefix}: {message}{Style.RESET_ALL}")
        logger.critical(message, extra={"ui_alert": True})
    elif severity == "WARNING":
        print(f"{Fore.YELLOW}{timestamp} - {log_prefix}: {message}{Style.RESET_ALL}")
        logger.warning(message, extra={"ui_alert": True})
    else:
        print(f"{Fore.CYAN}{timestamp} - {log_prefix}: {message}{Style.RESET_ALL}")
        logger.info(message, extra={"ui_alert": True})

# Show a message box alert
def show_alert_messagebox(title, message, type="warning"):
    """Displays a message box alert to the user."""
    root = tk.Tk()
    root.withdraw() 
    root.attributes("-topmost", True)

    if type == "info":
        messagebox.showinfo(title, message)
    elif type == "warning":
        messagebox.showwarning(title, message)
    elif type == "error":
        messagebox.showerror(title, message)
    # Try to close the hidden root window
    try:
        root.destroy()
    except tk.TclError:
        pass

# Terminate a process by PID
def terminate_process(pid, reason=""):
    """
    Terminates a process by its PID.
    """
    if pid is None:
        logger.warning("Attempted to terminate a process with None PID.")
        return
    # Try to terminate the process
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()
        proc.kill() 
        action_message = f"ACTION: Process '{proc_name}' (PID: {pid}) would be terminated."
        # Add reason if provided
        if reason:
            action_message += f" Reason: {reason}"

        logger.warning(action_message)
        alert_user(f"Process '{proc_name}' (PID: {pid}) identified for termination. (Simulated)", "WARNING")
    # Process not found
    except psutil.NoSuchProcess:
        logger.error(f"Cannot terminate: Process with PID {pid} not found.")

    # Permission denied
    except psutil.AccessDenied:
        logger.error(f"Access denied to terminate process PID {pid}.")
        alert_user(f"Access denied to terminate process PID {pid}. Elevated privileges may be required.", "ERROR")
    
    # Other errors
    except Exception as e:
        logger.error(f"Failed to terminate process PID {pid}: {e}")
        alert_user(f"Failed to terminate process PID {pid}: {e}", "ERROR")

# Terminate both a child and its parent process
def terminate_process_and_parent(child_pid, parent_pid, reason=""):
    """
    Terminates a child process and its parent process.
    """
    logger.warning(f"Attempting to terminate child process (PID: {child_pid}) and its parent (PID: {parent_pid}).")
    alert_user(f"Attempting to terminate child process (PID: {child_pid}) and its parent (PID: {parent_pid}). (Simulated)", "CRITICAL")
    # Terminate child process
    terminate_process(child_pid, reason=f"Child of suspicious chain. {reason}")

    # Check if parent PID is valid
    if parent_pid is not None and parent_pid != 0:
        try:
            parent_proc = psutil.Process(parent_pid)
            parent_name = parent_proc.name().lower()
            critical_system_processes = ["services.exe", "wininit.exe", "smss.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "explorer.exe"]
            # Skip termination if parent is a critical system proces
            if parent_name in critical_system_processes:
                logger.warning(f"Skipping termination of critical system parent process '{parent_name}' (PID: {parent_pid}).")
                alert_user(f"Skipping termination of critical system parent process '{parent_name}' (PID: {parent_pid}).", "WARNING")
            # Terminate non-critical parent process
            else:
                terminate_process(parent_pid, reason=f"Parent of suspicious chain. {reason}")
        # Parent process not found
        except psutil.NoSuchProcess:
             logger.debug(f"Parent process (PID: {parent_pid}) not found or already terminated.")
        
        # Permission denied
        except psutil.AccessDenied:
             logger.error(f"Access denied to check or terminate parent process PID {parent_pid}.")
             alert_user(f"Access denied to check or terminate parent process PID {parent_pid}.", "ERROR")
        # Other errors
        except Exception as e:
             logger.error(f"An error occurred while trying to terminate parent process PID {parent_pid}: {e}")

# Print results from process scan
def print_process_scan_results(results):
    # No results found
    if not results:
        print(Fore.GREEN + "No suspicious process activity found based on current criteria.")
        return

    # Results header
    print(Fore.CYAN + Style.BRIGHT + "\n--- Process Scan Results ---")
    for finding in results:
        # Suspicious process chain detected
        if finding["type"] == "Suspicious Process Chain":
            gup = finding["gup_process"]
            svchost = finding["svchost_process"]
            message = finding['message']
            alert_user(message, "CRITICAL")
            show_alert_messagebox("MALICIOUS PROCESS CHAIN DETECTED", message, "error") # Alert via messagebox
            print(f"{Fore.RED}{Style.BRIGHT}[ALERT] {message}")
            print(f"  Attacker Process: {gup.get('name','N/A')} (PID: {gup.get('pid','N/A')}, Path: {gup.get('exe', 'N/A')})")
            print(f"  Compromised/Spawned Process: {svchost.get('name','N/A')} (PID: {svchost.get('pid','N/A')}, Path: {svchost.get('exe', 'N/A')})")
            
            # If network connections exist
            if svchost.get('connections') and svchost['connections'] != "Access Denied or Error":
                print(f"{Fore.YELLOW}    Network Connections by {svchost.get('name','N/A')} (PID: {svchost.get('pid','N/A')}):")
                for conn in svchost['connections']:
                    laddr_str = f"{conn.get('laddr',())[0]}:{conn.get('laddr',())[1]}" if conn.get('laddr') else "N/A"
                    raddr_str = f"{conn.get('raddr',())[0]}:{conn.get('raddr',())[1]}" if conn.get('raddr') else "N/A"
                    print(f"      LADDR: {laddr_str}, RADDR: {raddr_str}, Status: {conn.get('status','N/A')}")
            terminate_process_and_parent(svchost.get('pid'), gup.get('pid'), reason="Suspicious GUP.exe -> svchost.exe chain")

        # svchost.exe with suspicious parent
        elif finding["type"].startswith("Suspicious svchost Parent"):
            svchost = finding.get("svchost_process", {})
            parent = finding.get("parent_process", {})
            message = finding.get('message', 'Suspicious svchost parent detected.')
            alert_user(message, "CRITICAL") 
            show_alert_messagebox("MALICIOUS PROCESS DETECTED", message, "error") 
            print(f"{Fore.RED}{Style.BRIGHT}[ALERT] {message}")
            print(f"  svchost.exe PID: {svchost.get('pid', 'N/A')}, Path: {svchost.get('exe', 'N/A')}")
            print(f"  Parent Process: {parent.get('name', 'N/A')} (PID: {parent.get('pid', 'N/A')})")
            # Parent is inaccessible
            if finding["type"] == "Suspicious svchost Parent (Parent Inaccessible)":
                print(f"  Note: Parent process was inaccessible or terminated.")
            terminate_process_and_parent(svchost.get('pid'), parent.get('pid'), reason="Suspicious svchost parent")
        
        # General process detail
        elif finding["type"] == "ProcessDetails":
            color = Fore.GREEN
            if finding.get("suspicion_notes"):
                color = Fore.YELLOW
                alert_user(f"Suspicion regarding PID {finding.get('pid','N/A')}: {finding['suspicion_notes']}", "WARNING")

            print(f"{color}Details for PID {finding.get('pid','N/A')}: {finding.get('name','N/A')}")
            print(f"  Path: {finding.get('exe', 'N/A')}")
            print(f"  Parent: {finding.get('parent_name', 'N/A')} (PPID: {finding.get('ppid', 'N/A')})")
            print(f"  CMD Line: {' '.join(finding.get('cmdline', []))}")

            if finding.get('suspicion_notes'):
                print(f"{Fore.YELLOW}  Notes: {finding['suspicion_notes']}")

            # DLLs info
            dlls_data = finding.get('dlls', [])
            if isinstance(dlls_data, list) and any(dll.strip() for dll in dlls_data):
                print(f"  Loaded DLLs (sample): {', '.join(dlls_data[:5])}{'...' if len(dlls_data) > 5 else ''}")
            elif isinstance(dlls_data, str): 
                print(f"  Loaded DLLs: {dlls_data}")

            # Network connections info
            connections_data = finding.get('connections', [])
            if isinstance(connections_data, list) and connections_data:
                print(f"  Network Connections:")
                for conn in connections_data[:3]: 
                    laddr_str = f"{conn.get('laddr',())[0]}:{conn.get('laddr',())[1]}" if conn.get('laddr') else "N/A"
                    raddr_str = f"{conn.get('raddr',())[0]}:{conn.get('raddr',())[1]}" if conn.get('raddr') else "N/A"
                    print(f"    LADDR: {laddr_str}, RADDR: {raddr_str}, Status: {conn.get('status','N/A')}")
                if len(connections_data) > 3: print("    ...")
            elif isinstance(connections_data, str):
                print(f"  Network Connections: {connections_data}")

# Print results from registry scan (HKCU\Run)
def print_registry_scan_results(results):
    if not results:
        print(Fore.GREEN + "No suspicious registry entries found in HKCU\\Run based on current criteria.")
        return

    print(Fore.CYAN + Style.BRIGHT + "\n--- Registry Scan Results (HKCU\\Run) ---")
    for entry in results:
        alert_user(f"Suspicious startup entry found: Name: '{entry['value_name']}', Data: '{entry.get('value_data','N/A')[:100]}...'", "WARNING")
        show_alert_messagebox("Suspicious Registry Entry", f"Suspicious startup entry found:\nName: '{entry['value_name']}'\nData: '{entry.get('value_data','N/A')[:100]}...'", "warning") # Alert via messagebox
        
        print(f"{Fore.YELLOW}[ALERT] Suspicious Startup Entry:")
        print(f"  Key Path: {entry.get('key_path','N/A')}")
        print(f"  Value Name: {entry.get('value_name','N/A')}")
        print(f"  Value Data: {entry.get('value_data','N/A')}")
        print(f"  Reasons:")
        for detail in entry.get('details',[]):
            print(f"    - {detail}")

# Print loaded DLLs for each process 
def print_all_dlls_results(results):
    if not results:
        print(Fore.GREEN + "No processes found or DLLs to list.")
        return
    print(Fore.CYAN + Style.BRIGHT + "\n--- All Processes and Loaded DLLs (Sample) ---")
    for item in results[:10]: 
        print(f"{Fore.WHITE}Process: {item.get('name','N/A')} (PID: {item.get('pid','N/A')})")
        dlls_data = item.get('dlls', [])
        if isinstance(dlls_data, list):
            if dlls_data:
                print(f"  DLLs ({len(dlls_data)}):")
                for dll_path in dlls_data[:5]:
                    print(f"    - {dll_path}")
                if len(dlls_data) > 5:
                    print(f"    - ... and {len(dlls_data) - 5} more.")
            else:
                print(f"  No DLLs loaded or accessible.")
        else:
            print(f"  DLLs: {dlls_data}")
    if len(results) > 10:
        print(f"{Fore.CYAN}... and {len(results) - 10} more processes.")

# Monitor new processes, scan with VirusTotal, alert and terminate if malicious
def monitor_processes(vt_api_key):
    """
    Monitors new processes, checks them with VirusTotal, alerts, and terminates malicious ones.
    """
    logger.info("Starting real-time process monitoring.")
    alert_user("Real-time process monitoring started.", "INFO")
    known_pids = set()

    # Track existing processes
    for proc in psutil.process_iter(['pid']):
        known_pids.add(proc.info['pid'])

    while True:
        time.sleep(5) # Check every 5 seconds
        current_pids = set()
        new_processes = []

        # Detect new processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                if pid not in known_pids:
                    new_processes.append(proc)
                    known_pids.add(pid) 
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue 

        if new_processes:
            logger.info(f"Detected {len(new_processes)} new processes.")
            for proc in new_processes:
                try:
                    proc_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'ppid'])
                    pid = proc_info['pid']
                    name = proc_info['name']
                    exe_path = proc_info.get('exe')
                    parent_pid = proc_info['ppid']
                    parent_name = "N/A"
                    # Get parent process name
                    try:
                        parent_proc = psutil.Process(parent_pid)
                        parent_name = parent_proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                         parent_name = "Inaccessible or Terminated"
                    logger.info(f"Analyzing new process: {name} (PID: {pid}, Parent: {parent_name} PID: {parent_pid})")

                    # Flag suspicious svchost.exe with unusual parent
                    is_suspicious_svchost_parent = False
                    if name.lower() == "svchost.exe":
                        if parent_name.lower() not in process_analyzer.STANDARD_SVCHOST_PARENTS:
                            is_suspicious_svchost_parent = True
                            message = f"Suspicious new svchost.exe (PID: {pid}) spawned by non-standard parent '{parent_name}' (PID: {parent_pid})."
                            alert_user(message, "CRITICAL") 
                            show_alert_messagebox("MALICIOUS PROCESS DETECTED", message, "error")
                            terminate_process_and_parent(pid, parent_pid, reason="Suspicious new svchost parent")

                     # If not svchost alert, check with VirusTotal
                    if not is_suspicious_svchost_parent and psutil.pid_exists(pid) and exe_path and vt_api_key:
                        logger.info(f"Checking file of new process {name} (PID: {pid}) with VirusTotal: {exe_path}")
                        vt_status, vt_pos, vt_total = static_analyzer.check_virustotal(exe_path)

                        if vt_status == "malicious":
                            message = f"MALICIOUS PROCESS DETECTED!\nName: {name}\nPID: {pid}\nPath: {exe_path}\nParent: {parent_name} (PID: {parent_pid})\nVirusTotal: {vt_pos}/{vt_total} malicious detections."
                            alert_user(message, "CRITICAL")
                            show_alert_messagebox("MALICIOUS PROCESS DETECTED", message, "error")
                            if name.lower() == process_analyzer.TARGET_CHILD_PROCESS_NAME.lower() and parent_name.lower() == process_analyzer.TARGET_PARENT_PROCESS_NAME.lower():
                                 terminate_process_and_parent(pid, parent_pid, reason="Malicious svchost spawned by GUP.exe")
                            else:
                                terminate_process(pid, reason="Malicious file detected by VirusTotal")

                        elif vt_status == "suspicious":
                            message = f"SUSPICIOUS PROCESS DETECTED!\nName: {name}\nPID: {pid}\nPath: {exe_path}\nParent: {parent_name} (PID: {parent_pid})\nVirusTotal: {vt_pos}/{vt_total} suspicious detections."
                            alert_user(message, "WARNING")
                            show_alert_messagebox("Suspicious Process Detected", message, "warning")

                        elif vt_status in ["api_key_missing", "error_hashing", "api_limit", "error", "error_request", "api_unauthorized"]:
                            logger.error(f"VirusTotal check failed for {name} (PID: {pid}): {vt_status}")
                        else:
                             logger.info(f"New process {name} (PID: {pid}) file is CLEAN according to VirusTotal ({vt_pos}/{vt_total}).")

                    elif not psutil.pid_exists(pid):
                         logger.debug(f"Process {name} (PID: {pid}) no longer exists. Skipping VT check.")
                    elif not exe_path:
                        logger.warning(f"Could not get executable path for new process {name} (PID: {pid}). Skipping VirusTotal check.")
                    elif not vt_api_key:
                        logger.info(f"VirusTotal API key not available. Skipping VT check for new process {name} (PID: {pid}).")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logger.debug(f"Could not analyze new process (PID potentially {proc_info.get('pid')}). It might have exited. Error: {e}")
                except Exception as e:
                    logger.error(f"An unexpected error occurred while analyzing a new process: {e}")


def main():
    parser = argparse.ArgumentParser(description="Advanced DLL Side-Loading Attack Detector. Monitors for specific GUP.exe behavior and other suspicious activities.")
    parser.add_argument("--scan-static", metavar="PATH", help="Path to a folder or file for static analysis.")
    parser.add_argument("--use-virustotal", action="store_true", help="Enable VirusTotal checking for static scans (requires API key).")
    parser.add_argument("--vt-api-key", metavar="KEY", help="VirusTotal API key (overrides config.ini).")

    parser.add_argument("--scan-processes", action="store_true", help="Scan running processes for GUP.exe -> svchost.exe pattern and other anomalies.")
    parser.add_argument("--scan-pid", metavar="PID", type=int, help="Get details and analyze a specific Process ID.")
    parser.add_argument("--list-all-dlls", action="store_true", help="List all processes and their loaded DLLs (can be very verbose).")

    parser.add_argument("--scan-registry", action="store_true", help="Scan HKCU\\CurrentVersion\\Run for suspicious entries.")

    parser.add_argument("--full-scan", metavar="PATH", help="Perform static scan on PATH, process scan, and registry scan. Use with --use-virustotal if desired.")
    parser.add_argument("--monitor", action="store_true", help="Enable real-time process monitoring.")

    args = parser.parse_args()

    vt_api_key_to_use = args.vt_api_key or utils.VT_API_KEY 

    # Checks if VirusTotal scanning should be enabled
    use_virustotal_in_scan = args.use_virustotal or (args.full_scan and args.use_virustotal) or args.monitor

    if use_virustotal_in_scan:
        if not vt_api_key_to_use:
            alert_user("VirusTotal API key is required for --use-virustotal, --full-scan with VT, or --monitor. Please provide it via --vt-api-key or in config.ini.", "ERROR")
            logger.error("VirusTotal API key missing for required VirusTotal scan.")
            static_analyzer.set_vt_api_key(None)
            if args.monitor:
                sys.exit(1)
        else:
            static_analyzer.set_vt_api_key(vt_api_key_to_use)
            masked_key = f"{'*' * (len(vt_api_key_to_use)-4)}{vt_api_key_to_use[-4:]}" if len(vt_api_key_to_use) > 4 else "****"
            logger.info(f"VirusTotal scanning enabled. API Key: {masked_key}")
    else:
        static_analyzer.set_vt_api_key(None)
        logger.info("VirusTotal scanning disabled for this run.")


    logger.info(f"Starting DLL Side-Loading Attack Detector at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Command line arguments: {sys.argv}")

    action_args = [args.scan_static, args.scan_processes, args.scan_pid, args.list_all_dlls, args.scan_registry, args.full_scan, args.monitor]
    if not any(action_args):
        parser.print_help()
        sys.exit(0)

    # Static scan (folder or file)
    if args.scan_static:
        if os.path.isdir(args.scan_static):
            results = static_analyzer.scan_folder(args.scan_static, use_virustotal_in_scan)
        elif os.path.isfile(args.scan_static):
            result = static_analyzer.scan_file(args.scan_static, use_virustotal_in_scan)
        else:
            alert_user(f"Static scan path not found: {args.scan_static}", "ERROR")
            logger.error(f"Static scan path not found: {args.scan_static}")

    # Process scans for suspicious patterns
    if args.scan_processes:
        process_findings = []
        process_findings.extend(process_analyzer.analyze_all_processes()) # GUP.exe -> svchost.exe pattern
        process_findings.extend(process_analyzer.analyze_svchost_parents()) # Suspicious svchost parents
        print_process_scan_results(process_findings)

    # Scan a specific PID
    if args.scan_pid:
        result = process_analyzer.scan_process_by_pid(args.scan_pid)
        if result:
            print_process_scan_results([{"type": "ProcessDetails", **result}])
        else:
            alert_user(f"Process with PID {args.scan_pid} not found or no details retrieved.", "INFO")

    # List all DLLs of all processes
    if args.list_all_dlls:
        results = process_analyzer.list_all_process_dlls()
        print_all_dlls_results(results)

    # Registry scan
    if args.scan_registry:
        results = registry_analyzer.scan_hkcu_run_key()
        print_registry_scan_results(results)

    # Full scan: static + process + registry
    if args.full_scan:
        alert_user(f"Starting Full Scan. Static Path: {args.full_scan}", "INFO")
        logger.info(f"Full Scan initiated. Static path: {args.full_scan}")
        if os.path.isdir(args.full_scan):
            static_results = static_analyzer.scan_folder(args.full_scan, use_virustotal_in_scan)
        elif os.path.isfile(args.full_scan):
            static_result = static_analyzer.scan_file(args.full_scan, use_virustotal_in_scan)
        else:
            alert_user(f"Full scan static path not found: {args.full_scan}", "ERROR")
            logger.error(f"Full scan static path not found: {args.full_scan}")

        process_findings = []
        process_findings.extend(process_analyzer.analyze_all_processes()) # GUP.exe -> svchost.exe pattern
        process_findings.extend(process_analyzer.analyze_svchost_parents()) # Suspicious svchost parents
        print_process_scan_results(process_findings)

        registry_results = registry_analyzer.scan_hkcu_run_key()
        print_registry_scan_results(registry_results)
        alert_user("Full Scan completed.", "INFO")

    # Real-time monitoring
    if args.monitor:
        if not vt_api_key_to_use:
            alert_user("VirusTotal API key is required for monitoring mode. Please provide it via --vt-api-key or in config.ini.", "ERROR")
            logger.error("VirusTotal API key missing for monitoring mode.")
            sys.exit(1)
        monitor_processes(vt_api_key_to_use)


    logger.info(f"DLL Side-Loading Attack Detector finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{Fore.BLUE}Scan session finished. Log file: {LOG_FILE}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        import ctypes
        # Check admin rights on Windows
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"{Fore.YELLOW}WARNING: Script is not running with Administrator privileges. Some scans (e.g., certain process details, system-wide DLL listing, process termination) might be limited or fail.{Style.RESET_ALL}")
            logger.warning("Script not running as Administrator. Functionality may be limited.")
    except ImportError:
        logger.info("ctypes module not found, skipping Administrator check (likely not on Windows or minimal Python install).")
        pass

    main()
