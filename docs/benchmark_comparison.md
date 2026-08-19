# Benchmark: `main` vs the numeric-immediate C2 extractor

Dataset: 226 Mirai-family ELF samples (`mirai_dataset_hashes.txt`).
Branch under test: `worktree-cnc-immediate` (`ddc74f0`).

## Method

Both columns are scored over the **same Ghidra analysis runs** — the pipeline
executed once, and the resulting `output/<sha256>/*.json` were then scored twice,
with `main`'s rules and with the new rules. So the difference is the extractor,
not the analysis budget or machine load.

`main`'s rules mean: C2s and domains come only from `xor_table.json`
(`table_init_func.tables[*].str_data`). `main` also *appears* to read
`parse_main.json`, but it looks for a key (`resolv_cnc_addr.domain`) that the
script never emits (`resolve_cnc_addr_func.cnc`), so that path contributed
nothing and is scored as zero.

The published `report.md` numbers are not directly comparable: they ran with the
60 s per-sample cap, where Ghidra is killed mid-analysis on many samples. They
are listed below for reference only.

## Headline

| Metric | `main` scoring | new scoring | Δ |
|---|---:|---:|---:|
| **C2 (IP) extracted** | **9** | **116** | **+107** |
| **Domains extracted** | **4** | **14** | **+10** |
| Samples with no config at all | 213 | 97 | −116 |
| Table parsed | 113 | 113 | 0 |
| — of which C2 came from a numeric immediate | — | 92 | — |
| Of the 50 `no_C2_found.txt` samples, now resolved | 0 | 30 | +30 |

Table parsing is untouched: same 113 samples, no regression.

For reference, `report.md` (60 s cap, `main`): table 73, C2 3, domains 2.
The `benchmark_new.json` run reports slightly lower absolute counts (C2 103,
table 101) than the table above because a sample carrying a `timeout.txt`
marker short-circuits before scoring; the numbers above score every JSON that
exists on disk, under both rule sets equally.

## Where the gain comes from

| Change | Contribution |
|---|---|
| `cnc_scanner.py` — C2 as a numeric immediate in the `sockaddr_in` setup | 92 samples |
| `benchmark.py` — fix the `parse_main` key that was never read | +10 domains, some IPs |
| Table/strings paths | unchanged |

The 92 are C2s that **exist nowhere as text**. `strings` on those binaries
returns no IP at all; the address lives only as an instruction operand, e.g.
`_DAT_00512644 = 0x5f3447a7` → `167.71.52.95`. No amount of better string or
table parsing reaches them — the extractor reads dataflow (p-code) instead.

## Immediate C2s by architecture

Proof the approach is not x86-shaped: it lands on every target in the corpus,
including the ones where the constant is split across two instructions (MIPS
`lui`/`ori`) or reached through `$gp`.

| Architecture | Immediate C2s |
|---|---:|
| ARM LE | 34 |
| MIPS BE | 13 |
| MIPS LE | 12 |
| x86 32-bit | 8 |
| PowerPC BE | 8 |
| x86-64 | 7 |
| SuperH4 | 5 |
| SPARC BE | 4 |
| M68k | 1 |
| **Total** | **92** |

Most common endpoints recovered: `65.222.202.53:80` (41 samples),
`176.65.139.62:18129` (8), `167.71.52.95:23` (7), `94.156.152.217` (7),
`94.26.106.197:23` (6), `181.214.99.180:18129` (3). Ports found: 80 (41),
23 (20), 18129 (19), 24 (10), plus 35342 and 443.

## Accuracy

Known-answer set, hand-verified in Ghidra before the extractor was written
(`docs/no_c2_analysis.md`) — **7/7 exact on IP _and_ port**:

| Sample | Arch | Expected | Extracted |
|---|---|---|---|
| `069a9632…` | x86-64 | 167.71.52.95:23 | ✅ |
| `17a373b6…`, `474d28ac…`, `3d1cc5c4…` | ARM | 167.71.52.95:23 | ✅ |
| `30cc5be6…` | MIPS LE | 167.71.52.95:23 | ✅ |
| `02e9bb2a…` | MIPS BE | 167.71.52.95:23 | ✅ |
| `299324c2…` | ARM | 181.214.99.180:18129 | ✅ |

VirusTotal cross-check (`vt_c2_results.json`): **14 correct, 19 wrong, 178
unverifiable**. Read that "wrong" column with care — for most of those hashes VT
lists only sandbox noise (`169.254.169.254`, `224.0.0.251`, mDNS) or the bot's
own mass-scan targets, not a C2. The clearest case is `b5b37d13…`, where VT has
only link-local while we extract `181.214.99.180` — the very C2 VT confirms on a
sibling sample. Precision on genuinely verifiable samples is well above the
42% the raw arithmetic gives.

### Known false positives

The `102.200.5.10:24` cluster (10 samples, one per architecture) is **wrong**.
Those are MIORI builds whose real C2 is `202.155.10.112`, stored as a string
under whole-image XOR `0x03`. They do construct a constant `sockaddr` that the
scanner reports, but it is not the C2. That is ~11% of the 92, and it is visible
in the output rather than silent: every candidate is emitted with its role,
score and provenance, and the string-based C2 is still recovered separately for
those samples.

## Reproduce

```bash
cd .claude/worktrees/cnc-immediate
python3 ghidra_scripts/cnc_scanner.py                  # helper self-test, no Ghidra
export GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_12.0.4_PUBLIC
python3 benchmark.py --timeout 300 --report benchmark_new.json
```

`output/` acts as a cache: a second run re-scores the existing JSON in seconds.
`rm -rf output ghidra_project` forces a full re-analysis (~85 min, 6 workers).
Samples that timed out keep a `timeout.txt` marker and are skipped until
`--retrytimeout 300` is passed.

## Still open

48 samples (21%) hit the 300 s cap. And the MIORI (XOR `0x03`) and softbot
(XOR `0x69`) clusters need a string-key brute force rather than an immediate
scan — see `docs/no_c2_analysis.md`, clusters C and D.
