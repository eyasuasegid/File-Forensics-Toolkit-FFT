# File Forensics Toolkit (FFT)

A command-line utility for rapid, initial security analysis of files. FFT is designed for security analysts, digital forensics investigators, and curious users who need to quickly determine the nature and potential risk of an unknown file.

It goes beyond simple file type identification, providing a multi-faceted report that includes cryptographic hashes, data randomness (entropy), embedded strings, and optional threat intelligence lookups.

---

## Features

*   **File Type Identification:** Uses file magic numbers to determine the true file type, ignoring the extension.
*   **Cryptographic Hashes:** Calculates MD5, SHA-1, and SHA-256 hashes, essential for file identification and threat intelligence lookups.
*   **Entropy Analysis:** Measures the file's data randomness to quickly determine if it's likely compressed, encrypted, or a packed executable.
*   **String Extraction:** Pulls readable ASCII and Unicode strings from the file, a key technique for finding IOCs (Indicators of Compromise) like IP addresses, URLs, or commands in malware.
*   **PE File Analysis:** If the file is a Windows Executable (`.exe`, `.dll`), it extracts basic metadata like compile time and imported libraries (DLLs).
*   **Image Metadata (EXIF):** If the file is a JPEG image, it extracts EXIF metadata, which can contain sensitive information like GPS coordinates, camera model, and dates.
*   **Threat Intelligence (Optional):** Integrates with the **VirusTotal API** to check the file's hash against a database of known malicious files.
*   **Flexible Output:** Provides both a human-readable console report and a machine-readable **JSON output** for integration with other tools.

---

## Installation

### Prerequisites
*   Python 3.7+

### Setup
1.  Clone this repository or download the files into a new folder.
    ```bash
    git clone <repository_url>
    cd file-forensics-toolkit
    ```
2.  Create and activate a Python virtual environment (recommended):
    ```bash
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```
4.  **(Optional) Set up VirusTotal API Key:**
    *   Get a free API key from [virustotal.com](https://www.virustotal.com/).
    *   Rename the `.env.example` file to `.env`.
    *   Open the new `.env` file and paste your API key into it: `VT_API_KEY="your_api_key_here"`

---

## Usage

The script is run from the command line, pointing to the file you want to analyze.

### Basic Analysis
```bash
python forensics.py "C:\path\to\your\file.ext"
```

### Advanced Options
*   **Extract and show all strings (can be long):**
    ```bash
    python forensics.py "C:\path\to\malware.exe" --strings
    ```
*   **Output the full report as JSON:**
    ```bash
    python forensics.py "C:\path\to\file.jpg" --json
    ```
*   **Check the file's hash against VirusTotal:**
    ```bash
    python forensics.py "C:\path\to\suspicious.dll" --virustotal
    ```

---

## Sample Output

```
============== FILE FORENSICS REPORT ==============
[+] Basic Information
    - File Name: 4BE3F3ED495B
    - File Size: 64.00 KB
    - File Type: data (application/octet-stream)
    - Extension Guess: .bin

[+] Cryptographic Hashes
    - MD5:    d41d8cd98f00b204e9800998ecf8427e
    - SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
    - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

[+] Entropy Analysis
    - Shannon Entropy: 7.9995 (Max: 8.0)
    - Analysis:        Extremely high entropy. Highly likely to be encrypted or well-compressed.

============== END OF REPORT ==============
```
