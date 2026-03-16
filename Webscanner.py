#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import time
import threading
import itertools

# ================= COLORS =================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ================= TOOLS =================
TOOLS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
}

# ================= UI =================
def banner():
    os.system("clear")
    print(f"""{RED}{BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗ ██████╗  ██████╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝██╔════╝██╔════╝ ██╔════╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ █████╗  ██║  ███╗██║  ███╗
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ ██╔══╝  ██║   ██║██║   ██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗███████╗╚██████╔╝╚██████╔╝
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝
{RESET}""")
    print(f"{GREEN}{BOLD}>>> AUTOMATED RECON STARTED <<<\n{RESET}")

# ================= SPINNER =================
def spinner(msg, stop_event):
    for c in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
        if stop_event.is_set():
            break
        print(f"\r{GREEN}[+] {msg} {c}{RESET}", end="", flush=True)
        time.sleep(0.1)
    print("\r", end="")

# ================= TOOL CHECK =================
def check_tool(tool):
    if shutil.which(tool) is None:
        print(f"{YELLOW}[!] {tool} not found{RESET}")
        ch = input(f"{CYAN}Install {tool}? Type Y: {RESET}").lower()
        if ch == "y":
            subprocess.call(TOOLS[tool], shell=True)
        else:
            print(f"{RED}[-] {tool} required. Exiting.{RESET}")
            sys.exit(1)

# ================= SAFE COMMAND RUN =================
def run_capture(cmd, outfile, live=False):
    with open(outfile, "w") as f:
        p = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in p.stdout:
            f.write(line)
            if live:
                print(f"{CYAN}  ↳ {line.strip()}{RESET}")
        p.wait()

# ================= MAIN =================
def main():
    banner()

    target = input(f"{CYAN}Enter target domain or IP: {RESET}").strip()
    if not target:
        print(f"{RED}[-] Invalid target{RESET}")
        sys.exit(1)

    for tool in TOOLS:
        check_tool(tool)

    os.makedirs(target, exist_ok=True)

    # ---------- SUBDOMAIN ENUM ----------
    print(f"\n{GREEN}{BOLD}[+] Subdomain Enumeration Started{RESET}")
    sub_file = f"{target}/subdomains.txt"

    stop = threading.Event()
    t = threading.Thread(target=spinner, args=("Gathering subdomains", stop))
    t.start()
    run_capture(f"subfinder -d {target} -silent", sub_file, live=True)
    stop.set(); t.join()

    print(f"{GREEN}[✓] Subdomains saved to {sub_file}{RESET}")

    # ---------- URL & JS DISCOVERY ----------
    print(f"\n{GREEN}{BOLD}[+] URL & JavaScript Discovery Started{RESET}")
    urls_file = f"{target}/urls.txt"
    js_file = f"{target}/jsfiles.txt"

    stop.clear()
    t = threading.Thread(target=spinner, args=("Crawling with Katana", stop))
    t.start()
    run_capture(f"katana -list {sub_file} -silent -jc", urls_file, live=True)
    stop.set(); t.join()

    # Extract JS files (correct method)
    js_set = set()
    with open(urls_file) as u:
        for line in u:
            if ".js" in line.lower():
                js_set.add(line.strip())

    with open(js_file, "w") as j:
        for js in sorted(js_set):
            j.write(js + "\n")
            print(f"{CYAN}  ↳ JS: {js}{RESET}")

    print(f"{GREEN}[✓] URLs saved to {urls_file}{RESET}")
    print(f"{GREEN}[✓] JS files saved to {js_file}{RESET}")

    # ---------- PARAMETER EXTRACTION ----------
    print(f"\n{GREEN}{BOLD}[+] Parameter Extraction Started{RESET}")
    param_file = f"{target}/parameters.txt"

    param_count = 0
    with open(urls_file) as u, open(param_file, "w") as p:
        for line in u:
            if "?" in line and "=" in line:
                p.write(line)
                print(f"{CYAN}  ↳ PARAM: {line.strip()}{RESET}")
                param_count += 1

    if param_count == 0:
        print(f"{YELLOW}[!] No parameters found{RESET}")
    else:
        print(f"{GREEN}[✓] Parameters saved to {param_file}{RESET}")

    # ---------- TRUE PARAMETER-BASED DAST ----------
    if param_count > 0:
        print(f"\n{GREEN}{BOLD}[+] Parameter-Based DAST Scan Started{RESET}")
        nuclei_out = f"{target}/nuclei_results.txt"

        nuclei_cmd = (
            f"nuclei -l {param_file} "
            f"-t vulnerabilities/xss/ "
            f"-t vulnerabilities/sqli/ "
            f"-t vulnerabilities/cves/ "
            f"-severity low,medium,high,critical "
            f"-silent"
        )

        stop.clear()
        t = threading.Thread(target=spinner, args=("Running Nuclei DAST scan", stop))
        t.start()
        run_capture(nuclei_cmd, nuclei_out, live=True)
        stop.set(); t.join()

        print(f"{GREEN}[✓] DAST results saved to {nuclei_out}{RESET}")
    else:
        print(f"{YELLOW}[!] Skipping DAST scan (no parameters){RESET}")

    print(f"\n{RED}{BOLD}>>> RECON DONE !! <<< {RESET}\n")

if __name__ == "__main__":
    main()