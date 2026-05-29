# YARA vs YARA-X Dynamic Benchmarking Suite

This repository contains benchmarking suite designed to the performance of legacy C-based **YARA** and the next-generation Rust-based **YARA-X**.
---

## 📁 Structured Corpus Architecture

Targets are structured modularly inside the `corpus/` folder:
*   **Subdirectories** (e.g., `corpus/local_clean/`): The folder name is the name of the corpus. It contains compressed `.zip` files representing the scan targets (malware simulation zips use the standard password `infected`).
*   **Hash List Files** (e.g., `corpus/pe_files.txt`): The file name (without extension) is the name of the corpus. It contains a list of SHA-256 hashes to fetch from VirusTotal.

```
yara-x-benchmarks/
├── corpus/                    # Structured input corpora
│   ├── local_clean/           # Clean corpus folder
│   │   └── clean.zip          # Compressed clean targets (~50MB)
│   └── pe_files.txt          # Hash list corpus (corpus name: 'vt_hashes')
├── targets/                   # Extracted scan targets directory (git-ignored)
│   ├── local_clean/           # Automatically unpacked clean files
│   └── pe_files/              # Automatically unpacked simulated malware files
├── rules/                     # Hand-curated rule sets for performance comparisons
│   ├── aho_corasic.yar        # Standard strings, hex sequences, and baseline indicators
│   ├── teddy.yar              # Simple rule with very few patterns, where YARA-X uses Teddy instead of Aho-Corasick.
│   └── pe.yar                 # Rules using the PE module.
├── manage_targets.py          # Structured target extractor, packager, and VT downloader
├── run_benchmarks.py          # Dynamic orchestrator running hyperfine and rendering reports
```

---


## 🚀 Quick Start

### 1. Setup & Install Dependencies
```bash
# Install hyperfine
brew install hyperfine

# Install python dependencies
pip install -r requirements.txt
```

### 2. Auto-Prepare target Corpora
Prepare all structured directories inside `corpus/` at once:
```bash
python3 manage_targets.py --prepare-all
```
*This extracts compressed `.zip` files under `corpus/` to their corresponding subdirectory inside `targets/`.*

### 3. Run Benchmarks
Execute the orchestrator script to auto-discover prepared targets, compile rules, and run the benchmarks:
```bash
python3 run_benchmarks.py
```

### 4. Cleanup Target Files
Safely remove all unpacked test files from your workspace:
```bash
python3 manage_targets.py --clean
```

---

## 🛡️ VirusTotal Integration

To configure a VirusTotal-driven hashlist corpus:

1. Set your VirusTotal API key:
   ```bash
   export VT_API_KEY="your_virustotal_api_key"
   ```
3. Run the prepare script for this specific corpus:
   ```bash
   python3 manage_targets.py --prepare pe_files
   ```

The downloaded targets are automatically saved to `targets/pe_files/` and will be dynamically discovered and scanned during the next benchmark run.
