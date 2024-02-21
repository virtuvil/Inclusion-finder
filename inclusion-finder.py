import sys
import re

def detect_file_inclusion_attacks(log_file_path):
    # Regular expression patterns for RFI and LFI attacks
    rfi_pattern = r"(?i)\binclude(\s|\+)+[\"']http"
    lfi_pattern = r"(?i)\binclude(\s|\+)+[\"']\.\."

    # Read the log file
    with open(log_file_path, 'r') as file:
        log_data = file.read()

    # Check for RFI attacks
    rfi_matches = re.findall(rfi_pattern, log_data)
    if rfi_matches:
        print("Remote File Inclusion (RFI) Attacks Detected:")
        for match in rfi_matches:
            print(f" - {match}")

    # Check for LFI attacks
    lfi_matches = re.findall(lfi_pattern, log_data)
    if lfi_matches:
        print("\nLocal File Inclusion (LFI) Attacks Detected:")
        for match in lfi_matches:
            print(f" - {match}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_file_inclusion_attacks.py <apache_access_log>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    detect_file_inclusion_attacks(log_file_path)

