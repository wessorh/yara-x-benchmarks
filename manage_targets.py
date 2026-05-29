#!/usr/bin/env python3
import os
import sys
import shutil
import zipfile
import subprocess
import argparse
import urllib.request

# Directories relative to this script
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(REPO_DIR, "corpus")
TARGETS_DIR = os.path.join(REPO_DIR, "targets")

# Standard PE files source to copy when packaging defaults
PE_SOURCE_DIR = "/Users/vmalvarez/Projects/yara-x/.venv/lib/python3.13/site-packages/pip/_vendor/distlib"

def setup_dirs():
    """Creates directories if they do not exist."""
    os.makedirs(CORPUS_DIR, exist_ok=True)
    os.makedirs(TARGETS_DIR, exist_ok=True)

def pack_defaults():
    """Generates default clean and simulated malware zips in corpus/ directory."""
    print("[*] Generating default corpora in 'corpus/'...")
    setup_dirs()

    # ----------------------------------------------------
    # 1. Generate local_clean default zip
    # ----------------------------------------------------
    clean_corpus_dir = os.path.join(CORPUS_DIR, "local_clean")
    os.makedirs(clean_corpus_dir, exist_ok=True)
    
    temp_clean_dir = os.path.join(TARGETS_DIR, "temp_clean_pack")
    os.makedirs(temp_clean_dir, exist_ok=True)

    print("  [*] Generating clean files...")
    lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 450000
    with open(os.path.join(temp_clean_dir, "lorem_ipsum_large.txt"), "w") as f:
        f.write(lorem)
        
    with open(os.path.join(temp_clean_dir, "clean_script.py"), "w") as f:
        f.write("""def main():
    print("This is a completely clean script with no matches.")
    for i in range(10):
        print(f"Index: {i}")

if __name__ == '__main__':
    main()
""")

    chunk = b"A" * 1024 * 1024
    with open(os.path.join(temp_clean_dir, "clean_binary_large.bin"), "wb") as f:
        for _ in range(25):
            f.write(chunk)

    clean_zip_path = os.path.join(clean_corpus_dir, "clean.zip")
    print(f"  [*] Packaging {clean_zip_path}...")
    try:
        subprocess.run(["zip", "-r", clean_zip_path, "."], cwd=temp_clean_dir, check=True, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(temp_clean_dir)

    # ----------------------------------------------------
    # 2. Generate simulated_malware default zip
    # ----------------------------------------------------
    malware_corpus_dir = os.path.join(CORPUS_DIR, "simulated_malware")
    os.makedirs(malware_corpus_dir, exist_ok=True)
    
    temp_malware_dir = os.path.join(TARGETS_DIR, "temp_malware_pack")
    os.makedirs(temp_malware_dir, exist_ok=True)

    print("  [*] Generating simulated malware files...")
    with open(os.path.join(temp_malware_dir, "sim_text_matches.bin"), "wb") as f:
        f.write(b"Calling VirtualAlloc inside the process...\n")
        f.write(b"Followed by CreateRemoteThread to inject...\n")
        f.write(b"And finally WriteProcessMemory to write the payload.\n")
        
    with open(os.path.join(temp_malware_dir, "sim_hex_matches.bin"), "wb") as f:
        f.write(bytes.fromhex("4d5a90000300000004000000ffff"))
        f.write(bytes.fromhex("558bec81ec"))
        
    with open(os.path.join(temp_malware_dir, "sim_regex_matches.bin"), "wb") as f:
        f.write(b"Host: api-server-malicious.dll\n")
        f.write(b"User-Agent: Mozilla/5.0/custom-agent/1.2\n")

    if os.path.exists(PE_SOURCE_DIR):
        for filename in ["w32.exe", "w64.exe"]:
            src = os.path.join(PE_SOURCE_DIR, filename)
            if os.path.exists(src):
                shutil.copy(src, os.path.join(temp_malware_dir, filename))

    malware_zip_path = os.path.join(malware_corpus_dir, "malware.zip")
    print(f"  [*] Packaging password-protected {malware_zip_path}...")
    try:
        subprocess.run(["zip", "-r", "-P", "infected", malware_zip_path, "."], cwd=temp_malware_dir, check=True, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(temp_malware_dir)

    # ----------------------------------------------------
    # 3. Generate default vt_hashes.txt file
    # ----------------------------------------------------
    vt_hash_path = os.path.join(CORPUS_DIR, "vt_hashes.txt")
    if not os.path.exists(vt_hash_path):
        print("  [*] Creating default 'corpus/vt_hashes.txt'...")
        with open(vt_hash_path, "w") as f:
            f.write("# Add sha256 hashes here to download from VirusTotal (one per line)\n")
            f.write("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")

    print("[+] Defaults successfully packaged in 'corpus/'.")

def extract_zip(zip_path, dest_dir):
    """Safely extracts zip, trying default password 'infected' if password protected."""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            try:
                zf.extractall(path=dest_dir)
            except RuntimeError as e:
                if 'password' in str(e):
                    # Try extracting with default password
                    zf.extractall(path=dest_dir, pwd=b"infected")
                else:
                    raise e
        print(f"  [+] Extracted: {os.path.basename(zip_path)}")
    except Exception as e:
        print(f"  [-] Failed to extract {os.path.basename(zip_path)}: {e}")

def prepare_directory_corpus(corpus_name):
    """Uncompresses all zip files under corpus/<corpus_name>/ to targets/<corpus_name>/."""
    src_dir = os.path.join(CORPUS_DIR, corpus_name)
    dest_dir = os.path.join(TARGETS_DIR, corpus_name)
    
    print(f"[*] Preparing corpus '{corpus_name}'...")
    os.makedirs(dest_dir, exist_ok=True)
    
    zips_found = False
    for item in os.listdir(src_dir):
        if item.lower().endswith(".zip"):
            zips_found = True
            extract_zip(os.path.join(src_dir, item), dest_dir)
            
    if not zips_found:
        print(f"  [!] Warning: No .zip archives found in {src_dir}.")

def prepare_vt_corpus(corpus_name):
    """Downloads files from VirusTotal for hashes in corpus/<corpus_name>.txt to targets/<corpus_name>/."""
    hashes_file = os.path.join(CORPUS_DIR, f"{corpus_name}.txt")
    dest_dir = os.path.join(TARGETS_DIR, corpus_name)
    
    print(f"[*] Preparing corpus '{corpus_name}'...")
    
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("  [!] Warning: VT_API_KEY environment variable not set. Skipping VirusTotal download.")
        print("  [!] Set it using: export VT_API_KEY='your_key' if you wish to prepare this corpus.")
        return
        
    with open(hashes_file, "r") as f:
        hashes = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
    if not hashes:
        print("  [!] Warning: No hashes found in hashes list.")
        return
        
    os.makedirs(dest_dir, exist_ok=True)
    print(f"  [*] Downloading {len(hashes)} file(s) from VirusTotal...")
    
    for sha256 in hashes:
        target_file = os.path.join(dest_dir, sha256)
        if os.path.exists(target_file):
            print(f"  [i] File {sha256} already exists, skipping download.")
            continue
            
        print(f"  [*] Downloading {sha256}...")
        url = f"https://www.virustotal.com/api/v3/files/{sha256}/download"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", api_key)
        
        try:
            import ssl
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, context=context) as response:
                with open(target_file, "wb") as out_file:
                    out_file.write(response.read())
            print(f"  [+] Downloaded {sha256} successfully.")
        except Exception as e:
            print(f"  [-] Failed to download {sha256}: {e}")

def prepare_corpus(corpus_name):
    """Prepares a single corpus by matching the name with directory or txt file."""
    setup_dirs()
    
    # Check if it is a directory corpus
    dir_path = os.path.join(CORPUS_DIR, corpus_name)
    if os.path.isdir(dir_path):
        prepare_directory_corpus(corpus_name)
        return
        
    # Check if it is a VirusTotal hashlist corpus
    hashes_file = os.path.join(CORPUS_DIR, f"{corpus_name}.txt")
    if os.path.isfile(hashes_file):
        prepare_vt_corpus(corpus_name)
        return
        
    print(f"[-] ERROR: Corpus '{corpus_name}' not found in 'corpus/'.")
    print("[-] Ensure either 'corpus/<name>/' directory or 'corpus/<name>.txt' hashes list exists.")
    sys.exit(1)

def prepare_all_corpora():
    """Finds and prepares all corpora under the corpus/ directory."""
    setup_dirs()
    
    if not os.listdir(CORPUS_DIR):
        print("[!] Warning: 'corpus/' directory is empty. Generating defaults first.")
        pack_defaults()
        
    print("[*] Preparing all corpora from 'corpus/'...")
    
    # Loop through items in corpus/
    for item in os.listdir(CORPUS_DIR):
        item_path = os.path.join(CORPUS_DIR, item)
        
        # Directory -> directory corpus
        if os.path.isdir(item_path):
            prepare_directory_corpus(item)
            
        # Text file -> VirusTotal corpus
        elif os.path.isfile(item_path) and item.lower().endswith(".txt"):
            corpus_name = os.path.splitext(item)[0]
            prepare_vt_corpus(corpus_name)

def clean_targets():
    """Wipes the targets/ directory completely."""
    print("[*] Wiping 'targets/' directory...")
    if os.path.exists(TARGETS_DIR):
        shutil.rmtree(TARGETS_DIR)
    os.makedirs(TARGETS_DIR, exist_ok=True)
    print("[+] Wiped successfully.")

def main():
    parser = argparse.ArgumentParser(description="Structured Yara Benchmarking Target Corpus Management.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--prepare",
        metavar="CORPUS_NAME",
        help="Prepare a specific corpus by unzipping its files or downloading its VT hashes."
    )
    group.add_argument(
        "--prepare-all",
        action="store_true",
        help="Auto-discover and prepare all corpora found under the 'corpus/' folder."
    )
    group.add_argument(
        "--pack-defaults",
        action="store_true",
        help="Generate baseline target zip files and default hash configs inside 'corpus/' folder."
    )
    group.add_argument(
        "--clean",
        action="store_true",
        help="Wipe the uncompressed files and targets directory completely."
    )
    
    args = parser.parse_args()
    
    if args.pack_defaults:
        pack_defaults()
    elif args.prepare:
        prepare_corpus(args.prepare)
    elif args.prepare_all:
        prepare_all_corpora()
    elif args.clean:
        clean_targets()

if __name__ == "__main__":
    main()
