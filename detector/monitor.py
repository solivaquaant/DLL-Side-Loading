import os
import pefile
import hashlib
import requests
import csv
import argparse
import psutil
import win32api
import win32con
import win32process
import winreg
import wmi

from colorama import Fore, Style, init
from dotenv import load_dotenv

# Load .env để lấy VirusTotal API key
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY") or "2995982d3e2e3f177a7293a67f5e7c3195c0358818511955901d6324abafdbb4"

if not VT_API_KEY:
    print("Missing VirusTotal API key.")
    exit(1)

init(autoreset=True)
LOG_FILE = "dll_scan_log.csv"

# Danh sách thư mục đáng ngờ
SUSPICIOUS_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.path.expanduser("~\\Downloads"),
]

# Danh sách tên DLL hệ thống cần cảnh giác khi bị giả mạo
KNOWN_SYSTEM_DLLS = {
    "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll", "ws2_32.dll",
    "shell32.dll", "ole32.dll", "gdi32.dll", "wininet.dll", "winmm.dll"
}

def get_dlls_of_process(pid):
    dlls = []
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
        dll_paths = win32process.EnumProcessModules(handle)
        for mod in dll_paths:
            path = win32process.GetModuleFileNameEx(handle, mod)
            if path.lower().endswith(".dll"):
                dlls.append(path)
    except Exception:
        pass
    return dlls

def has_signature(filepath):
    try:
        pe = pefile.PE(filepath)
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        return dir_entry.Size > 0
    except:
        return False

def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data['data']['attributes']['last_analysis_stats']['malicious']
    elif response.status_code == 404:
        return -1
    else:
        return None

def contains_suspicious_code(filepath):
    try:
        with open(filepath, "rb") as f:
            content = f.read()
            # Kiểm tra shellcode phổ biến
            if b"\x90\x90\x90" in content or b"\xEB" in content or b"powershell" in content.lower() or b"http://" in content or b"https://" in content:
                return True
    except:
        pass
    return False

def log_to_csv(data):
    write_header = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["Process", "PID", "DLL Name", "Path", "Signature", "VT", "Note"])
        writer.writerow(data)

def analyze_dll(dll_path, process_name="(static)", pid="-"):
    dll_name = os.path.basename(dll_path).lower()
    sig_status = "Signed" if has_signature(dll_path) else "Unsigned"
    vt_status = "Unknown"
    note = ""

    if sig_status == "Unsigned":
        print(Fore.YELLOW + f"[!] DLL unsigned: {dll_path}")

    try:
        file_hash = get_file_hash(dll_path)
        vt_result = check_virustotal(file_hash)
        if vt_result == -1:
            vt_status = "Not found"
        elif vt_result is None:
            vt_status = "VT error"
        elif vt_result > 0:
            vt_status = f"Malicious ({vt_result})"
            print(Fore.RED + f"[!] Malicious DLL detected by {vt_result} engines.")
        else:
            vt_status = "Clean"
    except Exception as e:
        vt_status = "VT error"

    # Kiểm tra code bất thường
    if contains_suspicious_code(dll_path):
        note += "Contains suspicious code; "
        print(Fore.MAGENTA + f"[!] DLL may contain shellcode or payload.")

    # So sánh với DLL hệ thống
    if dll_name in KNOWN_SYSTEM_DLLS:
        if not dll_path.lower().startswith(os.environ.get("SystemRoot", "C:\\Windows").lower()):
            note += "Possible DLL spoofing; "
            print(Fore.MAGENTA + f"[!] DLL {dll_name} may be spoofed (not in system path).")

    for suspicious_dir in SUSPICIOUS_DIRS:
        if dll_path.lower().startswith(suspicious_dir.lower()):
            note += "From suspicious directory; "
            print(Fore.YELLOW + f"[!] DLL loaded from suspicious directory: {suspicious_dir}")
            break

    log_to_csv([process_name, pid, dll_name, dll_path, sig_status, vt_status, note.strip()])

def scan_process(pid):
    try:
        proc = psutil.Process(pid)
        print(Fore.CYAN + f"\n[+] Scanning process: {proc.name()} (PID {pid})")
        dlls = get_dlls_of_process(pid)
        for dll in dlls:
            analyze_dll(dll, proc.name(), pid)
    except Exception as e:
        print(Fore.RED + f"Error scanning process {pid}: {e}")

def scan_all_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        scan_process(proc.info['pid'])

def scan_by_name(name):
    found = False
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == name.lower():
            scan_process(proc.info['pid'])
            found = True
    if not found:
        print(Fore.RED + f"No process found with name: {name}")

def scan_folder(folder):
    print(Fore.GREEN + f"\n[+] Static scanning folder (recursive): {folder}")
    if not os.path.isdir(folder):
        print(Fore.RED + "Folder not found.")
        return

    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.lower().endswith(".dll"):
                full_path = os.path.join(root, file)
                print(f"→ Scanning DLL: {full_path}")
                analyze_dll(full_path)
def check_registry_for_dlls():
    print(Fore.CYAN + "\n[+] Checking Registry for suspicious DLL references...")

    # Danh sách các key registry thường bị lạm dụng
    REG_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", None),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", None),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", None),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", None)
    ]

    for hive, path, value_name in REG_PATHS:
        try:
            with winreg.OpenKey(hive, path) as key:
                if value_name:
                    try:
                        val, _ = winreg.QueryValueEx(key, value_name)
                        if val and any(ext in val.lower() for ext in [".dll", ".exe"]):
                            print(Fore.YELLOW + f"[Registry] {path}\\{value_name} → {val}")
                            analyze_dll(val.strip(), "(registry)", "-")
                    except FileNotFoundError:
                        continue
                else:
                    # Liệt kê subkeys (ví dụ: Services hoặc IFEO)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            i += 1
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    val, _ = winreg.QueryValueEx(subkey, "ImagePath")
                                    if ".dll" in val.lower() or ".exe" in val.lower():
                                        print(Fore.YELLOW + f"[Registry] {path}\\{subkey_name}\\ImagePath → {val}")
                                        analyze_dll(val.strip(), "(registry)", "-")
                                except FileNotFoundError:
                                    pass
                        except OSError:
                            break
        except FileNotFoundError:
            continue

def check_services_for_dlls():
    print(Fore.CYAN + "\n[+] Checking Windows Services for suspicious DLLs...")

    c = wmi.WMI()
    for service in c.Win32_Service():
        path = service.PathName
        if not path:
            continue
        if ".dll" in path.lower():
            path_clean = path.strip('"').split(" ")[0]
            print(Fore.YELLOW + f"[Service] {service.Name} → {path_clean}")
            analyze_dll(path_clean, "(service)", "-")


def main():
    parser = argparse.ArgumentParser(description="DLL Side-Loading/Hijacking Scanner")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all running processes")
    parser.add_argument("-p", "--pid", type=int, help="Scan specific process by PID")
    parser.add_argument("-n", "--name", type=str, help="Scan process by name")
    parser.add_argument("-f", "--folder", type=str, help="Static scan DLLs in folder (not loaded yet)")
    parser.add_argument("--check-registry", action="store_true", help="Scan registry for DLL references")
    parser.add_argument("--check-services", action="store_true", help="Scan Windows services for DLLs")
    
    args = parser.parse_args()

    # Trong main():
    if args.check_registry:
        check_registry_for_dlls()
    if args.check_services:
        check_services_for_dlls()
    if args.all:
        scan_all_processes()
    elif args.pid:
        scan_process(args.pid)
    elif args.name:
        scan_by_name(args.name)
    elif args.folder:
        scan_folder(args.folder)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
