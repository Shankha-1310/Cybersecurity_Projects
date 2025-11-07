import argparse
import subprocess
import sys
from datetime import datetime

# --- Configuration ---
# Nmap commands are run with -sV (Service Version detection) and -p (port range)
# The -T4 option sets the speed to aggressive (T4), which is fast but can be noisy.

# --- Functions ---

def run_nmap_scan(target, ports, scan_type):
    """
    Executes the Nmap command using the subprocess module.
    
    Args:
        target (str): IP or hostname.
        ports (str): Port range in Nmap format (e.g., "1-1024" or "80,443").
        scan_type (str): Nmap scan flag (e.g., "-sS" for SYN scan, "-sT" for TCP connect).
    """
    
    # 1. Build the base command
    # -T4 (Timing template 4: Aggressive)
    # -sV (Service/Version detection)
    # -p (Port specification)
    command = [
        "nmap",
        scan_type,
        "-sV",
        "-T4",
        "-p", ports,
        target
    ]
    
    print("-" * 60)
    print(f"Starting Scan: {' '.join(command)}")
    print(f"Time started: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 60)

    try:
        # Execute Nmap command
        # subprocess.run is the modern way to run external commands
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True  # Raise an exception for non-zero exit codes
        )
        
        # 2. Print Nmap Output
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        # Handle Nmap specific errors (e.g., permission, host down)
        print(f"\n[ERROR] Nmap execution failed with return code {e.returncode}:")
        if "requires root privileges" in e.stderr:
            print("  --> Permission Denied: Run the script using 'sudo python3 script_name.py ...'")
        else:
            print(e.stderr)
    except FileNotFoundError:
        print("\n[ERROR] Nmap command not found. Ensure Nmap is installed and in your PATH.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] An unexpected error occurred: {e}")

    print("-" * 60)
    print(f"Scan finished at: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 60)

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A Python wrapper for the Nmap port scanner, ideal for Kali Linux.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("target", help="The target IP address or hostname.")
    parser.add_argument("ports", help="""
The port range to scan in Nmap format (e.g.):
  - Single port: 80
  - Range: 1-1024
  - Multiple ports: 21,22,80,443
  - All ports: 1-65535 (TAKES A LONG TIME!)
""")
    parser.add_argument("-t", "--type", default="sS", choices=["sS", "sT", "sU"], help="""
Select the scan type (Requires root/sudo for -sS and -sU):
  - **-sS** (SYN Scan): The fastest and stealthiest default (Requires sudo).
  - **-sT** (TCP Connect): Less stealthy, but can be run without sudo.
  - **-sU** (UDP Scan): Checks UDP ports (Requires sudo).
Default is -sS.
""")
    
    args = parser.parse_args()
    
    # Check for root privilege requirement for SYN and UDP scans
    if args.type in ["sS", "sU"] and sys.platform.startswith('linux') and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            # Check if running as root
            if not subprocess.run(['id', '-u'], capture_output=True, text=True, check=True).stdout.strip() == '0':
                print(f"[WARNING] Using scan type '{args.type}' often requires root privileges.")
                print("         Consider running the script with 'sudo python3 script_name.py ...'")
        except:
            pass # Ignore if 'id' command fails
            
    try:
        run_nmap_scan(args.target, args.ports, f"-{args.type}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)