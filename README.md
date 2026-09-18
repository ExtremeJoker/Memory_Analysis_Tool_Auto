# Memory Analysis Tool

A modular DFIR automation toolkit written in Bash, built to carve memory evidence with bulk_extractor/foremost, enumerate processes, network activity, command history, loaded modules, registry hives, and credential/SID data via Volatility (2 and 3), and verify integrity via SHA256 hashing at every evidence-handling step.

## About This Project
Bash-based automation system for investigating memory image files, aimed at reducing the repetitive manual setup that usually precedes actual forensic analysis.

The combination of bulk_extractor and foremost specifically to widen investigative coverage rather than rely on a single tool. foremost is strong for file/image carving, while bulk_extractor covers areas foremost doesn't focus on network traffic artifacts, credential-related strings, and executable files. Running both gives a broader first pass over a memory image than either tool alone.

A key goal was making sure automation didn't come at the cost of evidence integrity. I implemented SHA256 hash verification at each point where a file is moved or relocated during the pipeline, so I can confirm rather than assume that a file's contents are unchanged after being handled by the script. This isn't a full chain-of-custody system, but it gave me a concrete way to practice thinking about evidence handling with the same seriousness I'd want in a real investigative context.

This project also became a way to explore my own interest in DFIR and threat intelligence hands on not just running tools, but thinking about why an investigative workflow should be structured a certain way, what could go wrong with unverified automation, and how to build something an analyst could actually trust the output of.

## Features
Timestamped output and every run generates a unique, timestamped output directory, which supports an evidentiary record of exactly when each artifact was produced.
Dual-tool carving pipeline that combines bulk_extractor and foremost to widen investigative coverage: foremost for file/image carving, bulk_extractor for network traffic artifacts, credential-related strings, and executables.
Dependency checking and installation to validates that required tools are installed before running, and offers to install anything missing automatically.
SHA256 hash verification on evidence handling and that every output file is hashed before and after being moved into final storage, and the original evidence file is hashed at the start of the run and re-verified at the end, so integrity can be confirmed rather than assumed.
Modular, menu-driven string search analyst-directed search over extracted data, including categorized keyword search, per-keyword output files, keyword lists loaded from an external .conf file, and email address extraction via regex.
Confidence-tiered credential pattern detection an optional automated scan for password hash formats separating high-confidence structural matches from lower-confidence bare-hex matches to reduce false positives.
Run summary reporting, a closing summary of analysis duration, number of files recovered, and (only if run) results of the credential pattern scan.
Sourced, function-library architecture checks, carving/hashing, and search logic are split across separate library scripts and orchestrated by a single main script, so components can be tested or reused independently.

## Tech Stack
- **Language:** Bash
- **Tools:** apt, bulk_extractor, du, find, grep, foremost, sha256sum, strings, pip, volatility2, volatility3
- **Environment:** Developed and tested on Kali Linux

## Installation
1. Clone the repository

git clone https://github.com/ExtremeJoker/Memory_Analysis_Tool_Auto.git
cd Memory_Analysis_Tool_Auto

2. Make the scripts executable
chmod +x mem_anal_main.sh mem_anal_checks.sh mem_anal_carving.sh

3. Ensure prerequisites are available
The script will check for and offer to install missing tools automatically, but you'll need the following available on your system first:

- bash (developed/tested on Kali Linux's default bash)
- sudo privileges (required for tool installation and some carving operations)
- apt (Debian/Kali-based systems) and pip3 (for volatility3)

Note: this project was built and tested specifically on Kali Linux. It should work on other Debian-based distributions with apt, but hasn't been tested outside that environment.

4. Run a dependency check(optional,standalone)
You can validate your environment before your first real run

source mem_anal_checks.sh
checktools
installtools

## Usage
```bash
sudo ./mem_anal_main.sh
Prompted for
- File to analyse - filename (script will search the current directory tree for it)
- Output directory - All carved evidence, hashes, and reports will be stored. Created automatically  if it does not exist.

Example session:

$ sudo bash ./mem_anal_main.sh
sudo privilege detected
Please input the file OR the filename: file.mem
File for analysing found. Proceeding...
Please enter a directory to store the output: case_001
Begin validation check for files installed
Checks completed
...
Choose a string search method:
  1) Categorized keyword search (one file, sectioned by keyword)
  2) Per-keyword search (separate file per keyword)
  3) Keyword list from a .conf file
  4) Extract email addresses (regex)
  5) Automated credential/hash pattern scan
  6) Done - continue with rest of script
Selection [1-6]: 5
Scan complete. High-confidence: 0 | Possible MD5: 2 | Possible SHA1: 0 | Possible SHA256: 1
...
Time of Analysis: 47 seconds
Number of found files: 118

A credential/hash pattern scan was run during this session:
  High-confidence: 0 | Possible MD5: 2 | Possible SHA1: 0 | Possible SHA256: 1

Output structure (example):

case_001/
├── bulk_file.mem_26-09-14_08-01-47/
├── foremost_file.mem_Mon_Sep_14_.../
├── bulk_file.mem_26-09-14_08-01-47_manifest.sha256
├── foremost_file.mem_Mon_Sep_14_..._manifest.sha256
├── original_evidence_26-09-14_08-01-47.sha256
├── password_hash_report_26-09-14_08-01-47.txt
└── Strings_EMAIL.txt
```

## Disclaimer
This project was developed for educational purposes to deepen my understanding of digital forensics and memory analysis techniques. It is intended for learning and portfolio demonstration, not for use in real investigations or as a substitute for validated forensic tooling.

Only run this against memory images or files you own or have explicit permission to analyze. This script requires sudo privileges and can install system packages, so review the code before running it on any system you care about.

While care was taken to preserve evidence integrity (e.g. SHA256 verification at each handling step), this tool has not been forensically validated and should not be relied upon for legal, professional, or chain-of-custody purposes.

## What's Next
Volatility3 integration currently the script checks for and installs vol (Volatility3) as a dependency, but doesn't yet run it. The plan is to automate key plugins (e.g. pslist, netscan, hashdump) against the memory image and route their output into the existing evidence-handling pipeline same SHA256 verification and case-directory structure already used for bulk_extractor/foremost output.
