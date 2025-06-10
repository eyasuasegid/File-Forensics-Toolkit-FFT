import os
import sys
import hashlib
import math
import collections
import magic
import pefile
from PIL import Image
from PIL.ExifTags import TAGS
import argparse
import json
import requests
from dotenv import load_dotenv

# --- All function definitions (calculate_hashes, etc.) remain the same ---
# ... (omitting them here for brevity, assume they are present and unchanged) ...

def calculate_hashes(file_path):
    """Calculates MD5, SHA1, and SHA256 hashes for a file."""
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        return {"error": str(e)}
    return hashes

def calculate_entropy(file_path):
    """Calculates Shannon entropy of the file."""
    try:
        with open(file_path, 'rb') as f:
            byte_counts = collections.Counter(f.read())
        file_size = sum(byte_counts.values())
        entropy = 0.0
        for count in byte_counts.values():
            p_x = count / file_size
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return {"entropy": entropy}
    except Exception as e:
        return {"error": str(e)}

# --- All other analysis functions (extract_strings, etc.) are also unchanged ---
def extract_strings(file_path, min_len=4):
    strings = {"ascii": [], "unicode": []}
    # (Implementation is the same as before)
    return strings

def analyze_pe_file(file_path):
    # (Implementation is the same as before)
    return {}

def analyze_image_metadata(file_path):
    # (Implementation is the same as before)
    return {}

def check_virustotal(file_hash):
    # (Implementation is the same as before)
    return {}

### --- MAIN FUNCTION WITH MODIFIED LOGIC --- ###

def main():
    parser = argparse.ArgumentParser(description="File Forensics Toolkit (FFT)")
    parser.add_argument("file", help="Path to the file to analyze.")
    parser.add_argument("--strings", action="store_true", help="Display extracted strings.")
    parser.add_argument("--json", action="store_true", help="Output the full report in JSON format.")
    parser.add_argument("--virustotal", action="store_true", help="Check file hash against VirusTotal API.")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found at '{args.file}'")
        sys.exit(1)

    # --- Analysis Pipeline ---
    results = {}
    
    # Basic info
    file_type = magic.from_file(args.file)
    mime_type = magic.from_file(args.file, mime=True)
    results['basic_info'] = {
        "file_name": os.path.basename(args.file),
        "full_path": os.path.abspath(args.file),
        "file_size_bytes": os.path.getsize(args.file),
        "file_type_desc": file_type,
        "mime_type": mime_type
    }
    
    # Core forensics
    results['hashes'] = calculate_hashes(args.file)
    results['entropy_result'] = calculate_entropy(args.file) # Renamed for clarity
    if args.strings:
        results['strings'] = extract_strings(args.file)
    
    # Conditional Analysis
    if "PE32" in file_type:
        results['pe_info'] = analyze_pe_file(args.file)
    if mime_type.startswith("image/jpeg"):
        results['exif_data'] = analyze_image_metadata(args.file)
    
    # Optional Threat Intel
    if args.virustotal:
        sha256_hash = results.get('hashes', {}).get('sha256')
        if sha256_hash:
            results['virustotal_report'] = check_virustotal(sha256_hash)
        else:
            results['virustotal_report'] = {"error": "Could not calculate SHA256 hash to check VirusTotal."}

    # --- NEW: Smart Analysis Logic ---
    entropy = results.get('entropy_result', {}).get('entropy', 0)
    analysis_conclusion = "Low (Likely uncompressed text or structured data)."
    if entropy > 7.5:
        # High entropy detected, now apply context to differentiate
        is_known_compressed_type = any(keyword in mime_type.lower() for keyword in ['zip', 'gzip', 'jpeg', 'png', 'pdf'])
        is_pe_file = "PE32" in file_type
        
        if mime_type == 'application/octet-stream' and not is_pe_file:
            analysis_conclusion = "Extremely high entropy in an unknown file type. Highly likely to be ENCRYPTED."
        elif is_known_compressed_type or is_pe_file:
            analysis_conclusion = "High entropy consistent with a well-COMPRESSED file format or packed executable."
        else:
             analysis_conclusion = "High entropy. Could be compressed or encrypted." # Fallback
    elif entropy > 6.0:
        analysis_conclusion = "Medium entropy. Likely contains structured binary data or is lightly compressed."

    results['entropy_result']['analysis'] = analysis_conclusion
    # --- END OF NEW LOGIC ---

    # --- Output ---
    if args.json:
        print(json.dumps(results, indent=4))
    else:
        # Human-readable report
        bi = results['basic_info']
        size_kb = bi['file_size_bytes'] / 1024
        print("\n============== FILE FORENSICS REPORT ==============")
        print("[+] Basic Information")
        print(f"    - File Name: {bi['file_name']}")
        print(f"    - File Size: {size_kb:.2f} KB")
        print(f"    - File Type: {bi['file_type_desc']}")
        print(f"    - MIME Type: {bi['mime_type']}")

        h = results['hashes']
        print("\n[+] Cryptographic Hashes")
        print(f"    - MD5:    {h.get('md5', 'N/A')}")
        print(f"    - SHA1:   {h.get('sha1', 'N/A')}")
        print(f"    - SHA256: {h.get('sha256', 'N/A')}")

        # --- MODIFIED: Print the new smart analysis ---
        ent = results['entropy_result']
        print("\n[+] Entropy Analysis")
        print(f"    - Shannon Entropy: {ent.get('entropy', 0):.4f} (Max: 8.0)")
        print(f"    - Analysis:        {ent.get('analysis', 'N/A')}")
        # --- END OF MODIFICATION ---
        
        # (The rest of the printing logic remains the same)
        # ...
        print("\n============== END OF REPORT ==============")

if __name__ == "__main__":
    main()