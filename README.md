# String Pattern Matching Algorithms for Intrusion Detection Systems

## Project Overview
This project implements and compares multiple string pattern matching algorithms (Brute Force, KMP, Horspool, RabinKarp) for network intrusion detection on real-world network flow datasets.

## Executable Code

### Main Executable: `ids_runner.exe`

**Compilation Instructions:**

**Using Microsoft Visual C++ (MSVC):**
```cmd
cl /EHsc /std:c++17 algorithms.cpp /Fe:ids_runner.exe
```

**Using GCC:**
```bash
g++ -std=c++17 -O2 algorithms.cpp -o ids_runner
```

**Running from Command Line:**

Basic usage:
```cmd
ids_runner.exe --algo <algorithm> --data <dataset.csv> --patterns <signatures.txt> --text-bytes <size> --pattern-count <N> --trials <N>
```

**Command Line Arguments:**
- `--algo <algorithm>`: Algorithm to use (`brute`, `kmp`, `horspool`, `rabin`, `trie`, `hash`)
- `--data <path>`: Path to CSV dataset file
- `--patterns <path>`: Path to signature/pattern file (one pattern per line)
- `--text-bytes <N|NKB|NMB|NGB>`: Text size to process (e.g., `5MB`, `10MB`, `25MB`)
- `--pattern-count <N>`: Number of patterns to load from signature file
- `--trials <N>`: Number of experimental trials (default: 5)
- `--output <path>`: Optional CSV file to save detailed trial metrics
- `--quiet`: Suppress informational output
- `--help`: Display help message

**Example Commands:**

```cmd
REM Run brute force algorithm on Friday Morning dataset
ids_runner.exe --algo brute --data Friday-WorkingHours-Morning.pcap_ISCX.csv --patterns signatures.txt --text-bytes 25MB --pattern-count 10 --trials 5

REM Run KMP algorithm with output file
ids_runner.exe --algo kmp --data Tuesday-WorkingHours.pcap_ISCX.csv --patterns signatures.txt --text-bytes 10MB --pattern-count 5 --trials 5 --output results/kmp_10MB_p5.csv

REM Run Horspool algorithm (fastest)
ids_runner.exe --algo horspool --data Friday-WorkingHours-Morning.pcap_ISCX.csv --patterns signatures.txt --text-bytes 25MB --pattern-count 20 --trials 5
```

### Experiment Runner: `run_experiments.ps1`

**Running from PowerShell:**

```powershell
.\run_experiments.ps1 -DataFile "Friday-WorkingHours-Morning.pcap_ISCX.csv" -ResultsDir "results\fri_morning" -Algorithm "brute" -TextSizes @('1MB','5MB','10MB','25MB') -PatternCounts @(1,5,10,20) -Trials 5
```

**Parameters:**
- `-DataFile`: Dataset CSV file path
- `-ResultsDir`: Output directory for results
- `-Algorithm`: Algorithm name (`brute`, `kmp`, `horspool`, `rabin`)
- `-TextSizes`: Array of text sizes to test
- `-PatternCounts`: Array of pattern counts to test
- `-Trials`: Number of trials per configuration

**Example:**
```powershell
# Run all configurations for KMP algorithm
.\run_experiments.ps1 -DataFile "Friday-WorkingHours-Morning.pcap_ISCX.csv" -ResultsDir "results\fri_morning_updated" -Algorithm "kmp" -TextSizes @('1MB','5MB','10MB','25MB') -PatternCounts @(1,5,10,20) -Trials 5
```

### Data Processing Script: `add_intrusions.py`

**Running from Command Line:**
```cmd
python add_intrusions.py
```

This script adds intrusion entries to the network flow datasets. It processes all CSV files in the directory and adds various intrusion types based on patterns in `signatures.txt`.

## Output Files

All results are stored in the `results/` directory:
- **CSV files**: Detailed per-trial metrics (`[algorithm]_[size]_p[pattern_count].csv`)
- **LOG files**: Summary averages across trials (`[algorithm]_[size]_p[pattern_count].log`)

**File Naming Convention:**
- `brute_25MB_p10.csv` = Brute Force, 25MB text, 10 patterns
- `kmp_10MB_p5.log` = KMP, 10MB text, 5 patterns

## System Requirements

- **Operating System**: Windows (tested on Windows 10/11)
- **Compiler**: MSVC 2019+ or GCC 7+ with C++17 support
- **Python**: 3.7+ (for data processing scripts)
- **PowerShell**: 5.1+ (for experiment runner)

## Dataset Files

The project uses ISCX network flow datasets:
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Monday-WorkingHours.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`

## Signature File

`signatures.txt` contains intrusion patterns (one per line):
- BOT, DDOS, PORTSCAN, BRUTE FORCE, SQL INJECTION, XSS, MALWARE, etc.

## Performance Metrics

The executable outputs:
- **Execution time** (seconds)
- **Character comparisons** (for brute force, KMP, Horspool)
- **Hash operations** (for RabinKarp)
- **Token checks** (for hash lexicon)
- **Matches**: Total pattern matches found
- **True positives**: Matches on malicious rows
- **False positives**: Matches on benign rows

## Quick Start

1. **Compile the executable:**
   ```cmd
   cl /EHsc /std:c++17 algorithms.cpp /Fe:ids_runner.exe
   ```

2. **Add intrusions to datasets (optional):**
   ```cmd
   python add_intrusions.py
   ```

3. **Run a single test:**
   ```cmd
   ids_runner.exe --algo brute --data Friday-WorkingHours-Morning.pcap_ISCX.csv --patterns signatures.txt --text-bytes 5MB --pattern-count 10 --trials 5
   ```

4. **Run full experiment suite:**
   ```powershell
   .\run_experiments.ps1 -DataFile "Friday-WorkingHours-Morning.pcap_ISCX.csv" -ResultsDir "results\fri_morning" -Algorithm "brute"
   ```

## Results Summary

See `results/SUMMARY.md` for comprehensive analysis of all experimental results.

