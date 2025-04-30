import psutil
import os
import win32process
import win32api
import win32con
import pefile
import hashlib
import requests
import csv
from colorama import Fore, Style, init
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Kiểm tra nếu không có API key từ VirusTotal
if not VT_API_KEY:
    print("VirusTotal API key is missing. Please set it in the .env file")
    exit(1)

init()
LOG_FILE = 'dll_scan_log.csv'

# Các thư mục đáng ngờ thường bị lợi dụng để lưu DLL độc hại
SUSPICIOUS_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.path.expanduser("~\\Downloads")
]

# Lấy danh sách các DLL được load bởi tiến trình theo PID
def get_dlls_of_process(pid):
    '''
    Lấy danh sách các DLL được load bởi một tiến trình dựa trên PID.
    '''
    dlls = []
    try:
        # Mở tiến trình để truy cập thông tin về các module (DLL)
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
        dll_paths = win32process.EnumProcessModules(handle)
        for mod in dll_paths:
            # Lấy đường dẫn của mỗi DLL
            path = win32process.GetModuleFileNameEx(handle, mod)
            if path.lower().endswith(".dll"):
                dlls.append(path)
    except Exception:
        pass
    return dlls

# Kiểm tra file DLL có chứa chữ ký số không (cơ bản)
def has_signature(filepath):
    '''
    Kiểm tra xem file DLL có chữ ký số hay không.
    '''
    try:
        pe = pefile.PE(filepath)
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ].Size > 0
    except:
        return False

# Tính hash SHA-256 của file DLL
def get_file_hash(filepath):
    '''
    Tính toán giá trị hash SHA-256 của một file DLL.
    '''
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Kiểm tra file DLL trên VirusTotal
def check_virustotal(file_hash):
    '''
    Kiểm tra file DLL trên VirusTotal sử dụng hash SHA-256.
    Trả về số lượng các công cụ báo động nếu phát hiện phần mềm độc hại.
    '''
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
        return malicious_count
    elif response.status_code == 404:
        return -1  # not found
    else:
        return None

# Ghi log vào file CSV
def log_to_csv(data):
    '''
    Ghi kết quả quét vào file CSV.
    '''
    write_header = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["Process Name", "PID", "DLL Name", "DLL Path", "Signature", "VirusTotal", "Note"])
        writer.writerow(data)

# Hàm quét tiến trình theo PID
def scan_process(pid):
    '''
    Quét một tiến trình theo PID để kiểm tra các DLL bị load vào tiến trình đó.
    Nếu DLL là nguy hiểm, thông tin sẽ được ghi vào log.
    '''
    try:
        process = psutil.Process(pid)
        print(f"\nScanning process: {process.name()} (PID {pid})")
        dlls = get_dlls_of_process(pid)

        dll_locations = {}
        for dll in dlls:
            dll_name = os.path.basename(dll).lower()
            dll_locations.setdefault(dll_name, []).append(dll)

        for dll_name, paths in dll_locations.items():
            for path in paths:
                print(f"\n→ DLL: {path}")
                note = ""

                if has_signature(path):
                    sig_status = "Signed"
                else:
                    sig_status = "Unsigned"
                    print(Fore.YELLOW + "No digital signature found." + Style.RESET_ALL)

                try:
                    dll_hash = get_file_hash(path)
                    vt_result = check_virustotal(dll_hash)
                    if vt_result == -1:
                        vt_status = "Not found"
                        print(Fore.YELLOW + "Not found in VirusTotal." + Style.RESET_ALL)
                    elif vt_result is None:
                        vt_status = "Error"
                        print(Fore.RED + "VirusTotal error." + Style.RESET_ALL)
                    elif vt_result > 0:
                        vt_status = f"Malicious ({vt_result})"
                        print(Fore.RED + f"Detected as malicious by {vt_result} engines!" + Style.RESET_ALL)
                    else:
                        vt_status = "Clean"
                        print("Clean on VirusTotal.")
                except Exception as e:
                    vt_status = "Hash/VT Error"
                    print(Fore.RED + f"Hashing/VT error: {e}" + Style.RESET_ALL)

                if len(paths) > 1:
                    note += "DLL Hijacking suspected; "
                    print(Fore.MAGENTA + f"DLL Hijacking possible! Multiple locations for {dll_name}" + Style.RESET_ALL)

                for suspicious_dir in SUSPICIOUS_DIRS:
                    if path.lower().startswith(suspicious_dir.lower()):
                        note += "Loaded from suspicious directory; "
                        print(Fore.YELLOW + f"⚠ DLL loaded from suspicious directory: {suspicious_dir}" + Style.RESET_ALL)
                        break

                log_to_csv([process.name(), pid, dll_name, path, sig_status, vt_status, note.strip()])

    except psutil.NoSuchProcess:
        print(Fore.RED + f"Process {pid} not found." + Style.RESET_ALL)

# Quét tất cả các tiến trình đang chạy
def scan_all_processes():
    '''
    Quét tất cả các tiến trình đang chạy và kiểm tra DLL của chúng.
    '''
    for proc in psutil.process_iter(['pid', 'name']):
        scan_process(proc.info['pid'])

# Quét theo tên tiến trình
def scan_by_name(name):
    '''
    Quét các tiến trình đang chạy và kiểm tra DLL của các tiến trình có tên trùng với tên cung cấp.
    '''
    found = False
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == name.lower():
            found = True
            scan_process(proc.info['pid'])
    if not found:
        print(Fore.RED + f"No process found with name '{name}'." + Style.RESET_ALL)

def main():
    '''
    Hàm chính, sử dụng argparse để xử lý các tham số dòng lệnh.
    Cho phép quét theo PID, tên tiến trình hoặc tất cả các tiến trình.
    '''
    import argparse
    parser = argparse.ArgumentParser(description="DLL SideLoading / Hijacking / Proxying Detector")
    parser.add_argument("-p", "--pid", type=int, help="Scan specific process ID")
    parser.add_argument("-n", "--name", type=str, help="Scan process by name")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all running processes")
    args = parser.parse_args()

    if args.all:
        scan_all_processes()
    elif args.pid:
        scan_process(args.pid)
    elif args.name:
        scan_by_name(args.name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
