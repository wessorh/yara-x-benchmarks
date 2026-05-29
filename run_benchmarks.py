#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import shutil

# Paths relative to this script
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(REPO_DIR, "rules")
TARGETS_DIR = os.path.join(REPO_DIR, "targets")

# Tool paths
YARA_PATH = "/usr/local/bin/yara"
YARAC_PATH = "/usr/local/bin/yarac"
YARA_X_PATH = "/Users/vmalvarez/Projects/yara-x/target/release/yr"
HYPERFINE_PATH = "/opt/homebrew/bin/hyperfine"

def discover_rule_files():
    """Discovers all YARA rule files (.yar or .yara) in RULES_DIR."""
    rules = []
    if not os.path.exists(RULES_DIR):
        return rules
    for item in os.listdir(RULES_DIR):
        if item.lower().endswith((".yar", ".yara")):
            rules.append(item)
    return sorted(rules)

def check_dependencies():
    """Checks for the existence of the required executables and directories."""
    global YARA_PATH, YARAC_PATH, YARA_X_PATH, HYPERFINE_PATH
    print("[*] Verifying dependencies...")
    
    dependencies = {
        "yara": YARA_PATH,
        "yarac": YARAC_PATH,
        "yara-x (yr)": YARA_X_PATH,
        "hyperfine": HYPERFINE_PATH
    }
    
    all_ok = True
    for name, path in dependencies.items():
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(f"  [+] Found {name} at: {path}")
        else:
            # Fallback check in PATH
            in_path = shutil.which(os.path.basename(path))
            if in_path:
                print(f"  [+] Found {name} in PATH at: {in_path}")
                if name == "yara":
                    YARA_PATH = in_path
                elif name == "yarac":
                    YARAC_PATH = in_path
                elif name == "yara-x (yr)":
                    YARA_X_PATH = in_path
                elif name == "hyperfine":
                    HYPERFINE_PATH = in_path
            else:
                print(f"  [-] ERROR: {name} not found at {path} or in PATH.")
                all_ok = False
                
    if not all_ok:
        print("[-] Dependency check failed. Please install missing dependencies first.")
        sys.exit(1)
        
    # Check rule files
    rule_files = discover_rule_files()
    if not rule_files:
        print(f"[-] ERROR: No YARA rule files (.yar or .yara) found in rules/ directory '{RULES_DIR}'.")
        sys.exit(1)

def discover_active_corpora():
    """Returns a list of active target folders inside TARGETS_DIR."""
    corpora = []
    if not os.path.exists(TARGETS_DIR):
        return corpora
        
    for item in os.listdir(TARGETS_DIR):
        path = os.path.join(TARGETS_DIR, item)
        if os.path.isdir(path) and os.listdir(path):
            corpora.append(item)
            
    return sorted(corpora)

def run_hyperfine(cmd_yara, cmd_yara_x, title):
    """Runs hyperfine to compare legacy yara and yara-x."""
    import uuid
    temp_json = f"/tmp/hyperfine_{uuid.uuid4().hex}.json"
    print(f"  [*] Scanning: {title}...")
    
    hyperfine_cmd = [
        HYPERFINE_PATH,
        "--warmup", "3",
        "--min-runs", "10",
        "--export-json", temp_json,
        "-n", "Legacy YARA",
        cmd_yara,
        "-n", "YARA-X",
        cmd_yara_x
    ]
    
    try:
        subprocess.run(hyperfine_cmd, check=True)
        
        # Parse JSON results
        with open(temp_json, "r") as f:
            data = json.load(f)
            
        results = data.get("results", [])
        if len(results) < 2:
            return None
            
        legacy_res = results[0]
        yara_x_res = results[1]
        
        return {
            "legacy_mean": legacy_res["mean"],
            "legacy_stddev": legacy_res["stddev"],
            "yara_x_mean": yara_x_res["mean"],
            "yara_x_stddev": yara_x_res["stddev"],
            "speedup": legacy_res["mean"] / yara_x_res["mean"] if yara_x_res["mean"] > 0 else 0
        }
    except Exception as e:
        print(f"  [-] Hyperfine failed for: {title} - {e}")
        return None
    finally:
        if os.path.exists(temp_json):
            try:
                os.remove(temp_json)
            except Exception:
                pass

def format_result_row(rule_name, result):
    if not result:
        return f"| {rule_name:<18} | {'Error':<18} | {'Error':<18} | {'N/A':<10} |"
    
    legacy_str = f"{result['legacy_mean']*1000:.2f} ms ± {result['legacy_stddev']*1000:.2f}"
    yara_x_str = f"{result['yara_x_mean']*1000:.2f} ms ± {result['yara_x_stddev']*1000:.2f}"
    speedup_str = f"{result['speedup']:.2f}x"
    
    return f"| {rule_name:<18} | {legacy_str:<18} | {yara_x_str:<18} | {speedup_str:<10} |"

def main():
    check_dependencies()
    
    # Discover which corpora folders are prepared and active
    active_corpora = discover_active_corpora()
    rule_files = discover_rule_files()
    print(f"\n[*] Active target corpora discovered for scanning: {active_corpora}")
    print(f"[*] Rule files discovered: {rule_files}")
    
    try:
        results_scan = {} # Dict of corpus_name -> {rule_name -> result}
        
        # ---------------------------------------------------------------------
        # 2. DYNAMIC SCANNING BENCHMARKS PER DISCOVERED CORPUS
        # ---------------------------------------------------------------------
        for corpus in active_corpora:
            corpus_path = os.path.join(TARGETS_DIR, corpus)
            print(f"\n=========================================")
            print(f" Scanning corpus '{corpus}'")
            print("=========================================")
            
            results_scan[corpus] = {}
            
            for rf in rule_files:
                rule_path = os.path.join(RULES_DIR, rf)
                label = rf
                
                scan_yara = f"{YARA_PATH} {rule_path} {corpus_path}"
                scan_yara_x = f"{YARA_X_PATH} scan {rule_path} {corpus_path}"
                results_scan[corpus][label] = run_hyperfine(scan_yara, scan_yara_x, f"{corpus} ({label})")
            
        # ---------------------------------------------------------------------
        # RENDER DYNAMIC PERFORMANCE REPORT
        # ---------------------------------------------------------------------
        print("\n\n" + "="*75)
        print("                     BENCHMARK PERFORMANCE REPORT")
        print("="*75)
        
        # Render Scan results per Corpus dynamically
        section_num = 1
        for corpus in active_corpora:
            print(f"\n[{section_num}] SCANNING CORPUS: '{corpus}'")
            print("|" + "-"*76 + "|")
            print(f"| {'Rule File':<18} | {'Legacy YARA mean':<18} | {'YARA-X mean':<18} | {'Speedup':<10} |")
            print("|" + "-"*76 + "|")
            for rule_name, res in results_scan[corpus].items():
                print(format_result_row(rule_name, res))
            print("|" + "-"*76 + "|")
            section_num += 1
            
        print("="*75 + "\n")
        
    finally:
        pass

if __name__ == "__main__":
    main()
