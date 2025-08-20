import os
import sys
import argparse
import time
from colorama import Fore, Style, init

init(autoreset=True)

# === Helper Functions ===
def format_time(seconds):
    seconds = int(seconds)
    return time.strftime("%H:%M:%S", time.gmtime(seconds))

def show_progress(progress, elapsed=0, remaining=0, length=40):
    filled = int(length * progress // 100)
    bar = '■' * filled + '-' * (length - filled)
    sys.stdout.write(
        f"\r[{bar}] {progress:.1f}% "
        f"(elapsed: {format_time(elapsed)}, remaining: {format_time(remaining)})"
    )
    sys.stdout.flush()

def find_start_codes(data):
    start_codes = []
    i = 0
    while i < len(data) - 4:
        if data[i:i+3] == b'\x00\x00\x01':
            start_codes.append(i)
            i += 3
        elif data[i:i+4] == b'\x00\x00\x00\x01':
            start_codes.append(i)
            i += 4
        else:
            i += 1
    return start_codes

def parse_sei_message(sei_payload):
    i = 0
    payload_type = 0
    while i < len(sei_payload):
        byte = sei_payload[i]
        i += 1
        payload_type += byte
        if byte != 0xFF:
            break
    payload_size = 0
    while i < len(sei_payload):
        byte = sei_payload[i]
        i += 1
        payload_size += byte
        if byte != 0xFF:
            break
    sei_data = sei_payload[i:i + payload_size]
    return payload_type, sei_data

def check_file_exists(file_path, display_name):
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {display_name} not found: {file_path}")
        return None
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Found {display_name}: {os.path.basename(file_path)}")
    with open(file_path, "rb") as f:
        return f.read()

def make_sei_nal_from_bin(bin_data, max_unit_size=255):
    nal_units = []
    i = 0
    while i < len(bin_data):
        chunk = bin_data[i:i + max_unit_size]
        i += len(chunk)

        # Payload type
        payload_type = bytearray()
        val = 137
        while val >= 0xFF:
            payload_type.append(0xFF)
            val -= 0xFF
        payload_type.append(val)

        # Payload size
        payload_size = bytearray()
        val = len(chunk)
        while val >= 0xFF:
            payload_size.append(0xFF)
            val -= 0xFF
        payload_size.append(val)

        sei_message = payload_type + payload_size + chunk
        nal_header = b'\x4E\x01'  # SEI header
        nal_unit = b'\x00\x00\x01' + nal_header + sei_message
        nal_units.append(nal_unit)
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Generated SEI NAL units from bin data.")
    return nal_units

# === Extraction ===
def extract_hdr_vivid(data):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Extracting HDR Vivid data...")
    start_codes = find_start_codes(data)
    start_codes.append(len(data))
    all_hdr_vivid_data = bytearray()
    start_time = time.time()

    total_units = len(start_codes) - 1
    for idx in range(total_units):
        start, end = start_codes[idx], start_codes[idx + 1]
        nal_unit = data[start:end]

        if nal_unit.startswith(b'\x00\x00\x01'):
            nal_unit = nal_unit[3:]
        elif nal_unit.startswith(b'\x00\x00\x00\x01'):
            nal_unit = nal_unit[4:]
        if not nal_unit:
            continue

        nal_type = (nal_unit[0] >> 1) & 0x3F
        if nal_type == 39:
            sei_payload = nal_unit[2:]
            payload_type, sei_data = parse_sei_message(sei_payload)
            if payload_type == 137:
                all_hdr_vivid_data.extend(sei_data)

        # Update progress
        elapsed = time.time() - start_time
        progress = ((idx + 1) / total_units) * 100
        remaining = elapsed / (idx + 1) * (total_units - idx - 1) if idx > 0 else 0
        show_progress(progress, elapsed, remaining)
    print()  # newline

    if all_hdr_vivid_data:
        output_file = "hdr_vivid_full.bin"
        with open(output_file, "wb") as f:
            f.write(all_hdr_vivid_data)
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} HDR Vivid data extracted to: {output_file}")
    else:
        print(f"{Fore.RED}[WARN]{Style.RESET_ALL} No HDR Vivid data found.")

# === Injection ===
def inject_hdr_vivid(original_data, bin_file, output_file):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Injecting HDR Vivid data...")
    bin_data = check_file_exists(bin_file, "HDR Vivid bin file")
    if not bin_data:
        return

    sei_nal_units = make_sei_nal_from_bin(bin_data)
    start_codes = find_start_codes(original_data)
    start_codes.append(len(original_data))
    start_time = time.time()

    insert_index = 0
    total_units = len(start_codes) - 1
    for idx in range(total_units):
        start, end = start_codes[idx], start_codes[idx + 1]
        nal_unit = original_data[start:end]

        if nal_unit.startswith(b'\x00\x00\x01'):
            nal = nal_unit[3:]
        elif nal_unit.startswith(b'\x00\x00\x00\x01'):
            nal = nal_unit[4:]
        else:
            continue
        if not nal:
            continue

        nal_type = (nal[0] >> 1) & 0x3F
        if nal_type > 34:
            insert_index = start
            break

        # Progress
        elapsed = time.time() - start_time
        progress = ((idx + 1) / total_units) * 100
        remaining = elapsed / (idx + 1) * (total_units - idx - 1) if idx > 0 else 0
        show_progress(progress, elapsed, remaining)

    # Combine data
    final_data = bytearray()
    final_data.extend(original_data[:insert_index])
    for sei_nal in sei_nal_units:
        final_data.extend(sei_nal)
    final_data.extend(original_data[insert_index:])

    with open(output_file, "wb") as f:
        f.write(final_data)

    show_progress(100, time.time() - start_time, 0)
    print()  # newline
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} HDR Vivid data injected into: {os.path.basename(output_file)}")

# === Main ===
def main():
    parser = argparse.ArgumentParser(description="HDRVivid-Tool")
    parser.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 file")
    parser.add_argument("-e", "--extract-bin", action="store_true", help="Extract full HDR Vivid SEI data to a .bin file")
    parser.add_argument("-j", "--inject-bin", metavar="BIN", help="Inject HDR Vivid SEI data from a .bin file")
    parser.add_argument("-o", "--output", help="Output file when injecting")
    args = parser.parse_args()

    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting HDRVivid-Tool...")

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Read input file: {os.path.basename(args.input)}")
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Input file not found: {args.input}")
        return

    if args.extract_bin:
        extract_hdr_vivid(data)
    elif args.inject_bin:
        if not args.output:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} You must specify the output file using -o or --output")
            return
        inject_hdr_vivid(data, args.inject_bin, args.output)
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} You must specify either --extract-bin or --inject-bin")

if __name__ == "__main__":
    main()