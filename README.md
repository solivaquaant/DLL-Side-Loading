# DLL Side-Loading attack - PoC and Detection Tool

This repository demonstrates a DLL side-loading attack using `GUP.exe` and provides a comprehensive detection and monitoring tool to identify such attacks in real-time on Windows systems.

> **⚠️ Educational Use Only:**  
> This is a course project for the *"Malware Modus Operandi"* class at UIT. Everything in this repository is **strictly for educational purposes only**.

## 🧪 Proof-of-Concept (PoC)

The PoC illustrates DLL side-loading through `GUP.exe`, commonly associated with Notepad++. Two PoC components are included:

### 1. `dll-proxying.cpp`
- Mimics legitimate DLL exports from `libcurl.dll`.
- Displays a message box on load to confirm execution.
- Used as a minimal proxy to allow side-loading.

### 2. `poc.cpp`
Full attack simulation that:
- Proxies libcurl functions.
- Injects shellcode into `svchost.exe` (a legitimate system process).
- Creates a `.vbs` persistence script in `%APPDATA%`.
- Registers the script in the Windows Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) for persistence.

## 🔍 Detection and Monitoring Tool

A Python-based tool that provides multi-layered detection and real-time monitoring for DLL side-loading behavior.

### Features

- **Static analysis**:
  - Scan files and folders for unsigned binaries, `.vbs` launchers, and malicious indicators.
  - Optionally query [VirusTotal](https://www.virustotal.com) for reputation.

- **Process analysis**:
  - Detects suspicious process chains like `GUP.exe` spawning `svchost.exe`.
  - Identifies abnormal parent-child relationships for `svchost.exe`.
  - Lists loaded DLLs per process and checks against VirusTotal.

- **Registry analysis**:
  - Scans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for suspicious entries.
  - Flags `.vbs` scripts or entries referencing `gup.exe`.

- **Real-time monitoring**:
  - Continuously watches for new processes.
  - Flags suspicious activity, displays alerts, and optionally terminates malicious processes.

- **Logging & alerts**:
  - Color-coded terminal logs and persistent `.log` file.
  - GUI pop-up alerts via `tkinter`.

