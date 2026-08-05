# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cross-architecture Mirai config extractor. Three standalone Ghidra/Jython scripts in `ghidra_scripts/` reverse the Mirai XOR-obfuscation scheme and dump config (C2, credential list, DoS vectors) as JSON. Everything else in the repo is harness or evaluation around those three scripts.

## Commands

```bash
# Single sample (output lands in ./output/<SHA256>/)
GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_12.0.4_PUBLIC ./runner.sh <ELF_FILE>
./runner.sh --keep-project <ELF_FILE>   # keep the Ghidra project for GUI inspection

# Corpus benchmark (6 concurrent headless workers)
python3 benchmark.py                          # all hashes in mirai_dataset_hashes.txt
python3 benchmark.py --timeout 120            # per-sample timeout
python3 benchmark.py --retrytimeout 300       # re-run only samples that previously timed out

# VirusTotal ground truth for C2s (needs VT_API_KEY in .env)
python3 vt_c2_extractor.py
```

There is no test suite and no linter. The benchmark **is** the regression test: run it before and after touching a Ghidra script and compare `table_success` / `c2_success` rates in `benchmark_report.json`.

Scripts can also be run by copy-pasting into Ghidra's GUI Jython interpreter (Window → Jython) against an already-open binary — useful when debugging one stubborn sample.

## Architecture

`runner.sh` is the entry point: it hashes the ELF, reads `readelf -h` to map (Machine, Class, Data) → a Ghidra `-processor`/`-cspec` pair, then invokes `analyzeHeadless` once with all three scripts as `-postScript`, each writing its own JSON. **Adding an architecture means two edits**: a new branch in `runner.sh`'s dispatch chain, and the matching language ID added to the `ARCH_*` constants + `LANGS` list in each of the three scripts (they gate arch-specific decompiler/varnode handling on it).

The three scripts target different Mirai source files and are independent:

- `xor_table.py` (largest) — `table.c`. Recovers the table XOR key from `table_init()`, walks `table_unlock_val`/`add_entry` call sites, decodes every table entry. Yields C2, scan receiver, DoS params.
- `xor_scanner.py` — `scanner.c`. Recovers the scanner key, walks `add_auth_entry()` calls, decodes the telnet user/pass/weight brute-force list.
- `parse_main.py` — `main.c` / `attack.c`. Finds `main()` by decompiled-C signature heuristics, then `resolve_cnc_addr()` (plaintext/immediate C2) and `attack_init()` (registered DoS vectors).

All three share the same shape: `defUndefinedFuncs()` to recover functions Ghidra missed → `DecompInterface` decompilation → pattern-match the decompiled C and P-code (`INT_XOR`, `CALL`/`CALLIND` mnemonics) to locate the target function → decode bytes. Extraction is heuristic on decompiler output, so it is brittle across compilers and Mirai forks — a change that fixes one variant frequently regresses others, which is why the benchmark exists.

Output contracts are pinned by `jsonschema/*_jsonschema.json`, with worked examples in `sample/`. Keep them in sync when adding output keys.

## Constraints

- Ghidra scripts run under **Jython 2.7** inside Ghidra — Python 2 syntax only, stdlib only, no pip packages. `.python-version` is 2.7.18 for this reason. The host-side tooling (`benchmark.py`, `vt_c2_extractor.py`) is Python 3.
- Samples must be **unpacked** before analysis (UPX-packed binaries will not extract).
- `benchmark.py` hardcodes `MALWARE_DIR` at the top; it is machine-specific and expects files named by their SHA256.
- Malware corpus, `.env`, and `output/` are local only — never commit sample binaries or the VT key.

## Findings notes

`report.md` and `docs/no_c2_analysis.md` record the current failure analysis (which hashes miss C2 extraction and why); `no_C2_found.txt` is the working list of those hashes. Update them when the benchmark numbers move.
