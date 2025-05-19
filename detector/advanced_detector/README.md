
python main.py --scan-static "C:\Program Files\Notepad++\updater"

python main.py --scan-static "C:\Program Files\Notepad++\updater" --use-virustotal 

python main.py --scan-registry

python main.py --monitor --use-virustotal

<!-- tong hop 3 cai tren -->
python main.py --full-scan "C:\Program Files\Notepad++\updater" --use-virustotal 

<!-- --focus on gup.exe and svchost.exe-- -->

python main.py --scan-processes

<!-- --having errors at the moment-- -->

python main.py --scan-by-name

python main.py --scan-pid 1234

python main.py --list-all-dlls

