# Why mirai-toushi found no config for the 50 `no_C2_found.txt` samples

Static analysis only (Ghidra MCP + byte/XOR scans). No execution, no emulation, no debugging.

Sample source: `/home/thomas/data/malware/mirai2/merged/<md5>`.

## TL;DR

All 50 are IoT botnet ELFs (Mirai lineage or Mirai-derived). None are packed
(entropy 5.0–7.0, no UPX). The extractor misses them for two distinct reasons:

1. **C2 is not a string at all** — it is a 32-bit numeric literal assigned
   straight into a global `sockaddr_in` in `main` (`sin_addr = 0x…`,
   `sin_port = htons(…)`). Nothing to find in the string table or in the
   Mirai `table_init` blob. (~37 of 50 samples.)
2. **String obfuscation is not Mirai's scheme** — whole-image single-byte XOR
   with a non-standard key (0x03, 0x69), no `table_init`/`table_unlock_val`
   function at all, so both the table parser and the plaintext-strings
   fallback come up empty. (~12 of 50 samples.)

## Cluster breakdown

| Cluster | Count | Family | String obf | Where the C2 lives | Why toushi missed it |
|---|---|---|---|---|---|
| A | 6 | **IZ1H9 / "FROSTED"** | Mirai table, key `0xbaadf00d` (byte key `0xea`) | numeric literal in `main` | table exists and is decoded, but contains no CNC domain/port entry |
| B | 31 | **"boatnet"/"yamaha"** Mirai fork | classic `0xdeadbeef` (`0x22`), plus much of the corpus left plaintext | numeric literal in `main` | no `table_init` recognised; C2 never appears as a string |
| C | 11 | **MIORI** | whole-image XOR `0x03` | plaintext IP *inside* the XOR-0x03 blob | non-Mirai obfuscation, no table structure |
| D | 1 | "softbot" loader variant (`38ea4d…`) | whole-image XOR `0x69` | 4 duckdns domains in a null-padded slot array | same as C, unknown key |
| E | 2 | outliers (`40cfee…`, `847e33…`) | unknown / n/a | — | see notes below |

## Cluster A — IZ1H9 / FROSTED (6 samples)

Members: `069a9632…`, `30cc5be6…`, `02e9bb2a…`, `17a373b6…`, `474d28ac…`, `3d1cc5c4…`
(x86-64, MIPS LE/BE, ARM ×3).

* Mirai string table is present and **is** decoded by the pipeline: 48 entries,
  key `0xbaadf00d` → byte key `0xea` (vs stock Mirai `0xdeadbeef`/`0x22`).
* Table id 1 — the slot stock Mirai uses for `TABLE_CNC_DOMAIN` — holds the
  taunt `FROSTED IS HERE NIGGA`. There is **no** CNC domain and no CNC port
  entry anywhere in the 48 slots. Other slots are the usual IZ1H9 set:
  `/bin/busybox IZ1H9`, `IZ1H9: applet not found`, Huawei
  `POST /ctrlt/DeviceUpgrade_1` exploit blob, watchdog paths, `dvrHelper`,
  `TSource Engine Query`, telnet keyword slots.
* Ghidra decompile of `main` in `069a9632…` (`FUN_004068f0`, x86-64):

  ```c
  _DAT_00512640 = 2;            // sin_family = AF_INET
  _DAT_00512644 = 0x5f3447a7;   // sin_addr   = 167.71.52.95
  _DAT_00512642 = 0x1700;       // sin_port   = 0x0017 = 23
  FUN_00407780();               // table_init
  ```

  **C2 = 167.71.52.95:23** (DigitalOcean). The same 4 bytes `a7 47 34 5f`
  appear literally in `17a373b6…`, `474d28ac…`, `3d1cc5c4…`; in the two MIPS
  builds the constant is split across `lui`/`ori`, so a byte search does not
  hit it — a decompiler pass is required there.

## Cluster B — "boatnet"/"yamaha" fork (31 samples)

Largest group. Markers (plaintext in the binaries): `boatnet.{arm,arm5,arm6,arm7,mips,mpsl,m68k,x86,x86_64}`,
`yamaha.{…}`, `softbot.{arm,mpsl}`, killer strings `[0clKillerEXE]`,
`[0clKillerMaps]`, `[0clKillerStat]`, `im in deep sorrow.`, target process
names `Blink_Cloud`, `sys_monitor_cnr`, `lte_mgr`, `main_mgr`, `msg_center`,
`dockerd`.

* Some strings still use the stock `0x22` (`0xdeadbeef`) byte key (e.g.
  `TSource Engine Query`, `APPLET`, `ENABLE`, `SYSTEM`) but they are laid out
  as loose globals — the `table_init`/`table_unlock_val` pair the pipeline
  keys on is gone, so `xor_table.py` returns nothing (`table_lock_val_func`
  and `table_init_func` absent in `output/`).
* C2 is a literal. Ghidra on `299324c2…` (ARM, `main` = `0x000100fc` reached
  via `__libc_start_main` pointer at `0x00010820`):

  ```c
  *DAT_000107ac = 2;                              // sin_family
  *(sockaddr+4) = htonl_like(DAT_000107b0);       // DAT_000107b0 = 0xb5d663b4
  *(sockaddr+2) = htons_like(DAT_000107b4);       // DAT_000107b4 = 0x000046d1
  ```

  `0xb5d663b4` → **181.214.99.180**, port `0x46d1` → **18129**.
  The literal `b5 d6 63 b4` also occurs in `29ac6da8…`, `710077bb…`,
  `4ddda711…`, `f73f3f31…`, so at least 6 of the 31 share that C2; the rest
  need the same `main` walk per sample (other builds encode the constant with
  arch-specific split immediates).

## Cluster C — MIORI (11 samples)

Members: `ae903375…`, `bde323b7…`, `e5ef5836…`, `719d6c26…`, `6c638105…`,
`ecb631d4…`, `39c4e32f…`, `e35ba778…`, `1a907dd4…`, `2e907c29…`, `1d1b0706…`.

* **Every** printable string in the image is XOR `0x03` — including
  `libc.so.6`, `socket`, `connect`, `/proc/…`. There is no Mirai table.
* Decoding at `0x03` yields the full config in the clear:
  * **C2 `202.155.10.112`** (present in all 11)
  * banner `your device just got infected to a bootnoot`
  * `/bin/busybox MIORI`, `MIORI: applet not found`
  * a full telnet credential list (`vizxv`, `xc3511`, `Zte521`, `taZz@23495859`,
    `telecomadmin`, `OxhlwSG8`, `tlJwpbo6`, `S2fGqNFs`, …)
  * watchdog paths, `TSource Engine Query`.
* Missed because both extraction paths assume either the Mirai table structure
  or plaintext; a plain "brute all 256 single-byte keys and regex for IOCs"
  pass would have caught this cluster instantly.

## Cluster D — `38ea4d20…` (softbot variant)

* Strings XOR `0x69`. Decoding gives a null-padded slot array of C2 domains:
  `cvawrs.duckdns.org`, `fasdv.duckdns.org`, `savaswsd.duckdns.org`,
  `vmklsfdv.duckdns.org`, plus a `…n.my.id` entry, and loader names
  `softbot.arm`, `softbot.mpsl`, `wget http://%s/%s/%s -O %s`.
* Same failure mode as cluster C (non-standard single-byte key, no table).

## Cluster E — outliers

* `847e3311…` — 1 KB MIPS ELF, 5 strings, contains `MIRAI` and `GET /`. Too
  small to be a bot; a stub/dropper or a truncated artefact. Nothing to
  extract; should arguably be dropped from the benchmark denominator.
* `40cfee29…` — 169 KB MIPS, only three useful plaintext strings
  (`/proc/self/exe`, `/bin/busybox`, `[watchdog/0]`). No single-byte key
  produces recognisable Mirai strings, so it uses a multi-byte / per-string
  scheme. Unresolved; needs a decompiler pass.

## Implications for the extractor

1. **A table-less path is required.** For ~37 of 50 samples the only place the
   C2 exists is an immediate in `main`. The pattern is stable across forks:
   locate the global written with `AF_INET` (`= 2`), then take the two
   siblings written into the same struct (`+2` = port via `htons`, `+4` =
   address via `htonl`). Both IZ1H9 and boatnet builds match it verbatim, on
   x86-64 and ARM.
2. **Brute-force the string key instead of assuming `0xdeadbeef`.** Scoring
   all 256 single-byte keys against a marker word list (`/bin/busybox`,
   `/proc/`, `watchdog`, `TSource Engine Query`) recovers clusters C and D and
   confirms A, at negligible cost. It also correctly reports A's key as
   `0xea` (`0xbaadf00d`).
3. `table_init` presence is not evidence a C2 is in the table — IZ1H9 keeps
   the table and moves the C2 out of it. The pipeline should not stop after a
   successful table parse.

## Status: cluster A + B are handled now

`ghidra_scripts/parse_main.py` (the `cnc_immediates` scan) implements point 1 above. It anchors on the
socket setup shape in p-code — a write of `AF_INET` (2), then constant writes at
`+2` (port) and `+4` (address) into the same struct — instead of on how the C2
is stored. It resolves literal pools (ARM/MIPS materialise 32-bit constants
through them), `htons()`/`htonl()` wrappers, `lui`/`ori` split immediates, and
`$gp`-relative stores (via symbolic base+offset grouping when the absolute
address is unknowable). Candidates are ranked with a role guess so the DNS
resolver and the `:48101` single-instance bind never win.

Confirmed on the known-answer set (IP **and** port exact):

| Sample | Arch | Result |
|---|---|---|
| `069a9632…` | x86-64 | 167.71.52.95:23 |
| `17a373b6…`, `474d28ac…`, `3d1cc5c4…` | ARM | 167.71.52.95:23 |
| `30cc5be6…` | MIPS LE | 167.71.52.95:23 |
| `02e9bb2a…` | MIPS BE | 167.71.52.95:23 |
| `299324c2…` | ARM | 181.214.99.180:18129 |

Clusters C (MIORI, XOR 0x03) and D (softbot, XOR 0x69) are still open — those
need a string-key brute force, not an immediate scan.

### Benchmark, full 226-sample set

Scored twice over the *same* Ghidra runs, so the difference is the extractor,
not the analysis budget:

| Metric | main-branch scoring | with `parse_main.py` (`cnc_immediates`) |
|---|---|---|
| C2 extracted | 9 | 103 |
| of which numeric immediates | — | 92 |
| Domains | 4 | 4 |
| Table parsed | 113 | 113 |

(The published `report.md` baseline says 3 C2s; it ran with a 60 s per-sample
cap. At the 300 s cap used here the old scoring reaches 9. Table parsing is
untouched — no regression.)

VT cross-check: 14 correct, 19 "wrong", 178 unverifiable. Most of the "wrong"
bucket is VT's fault, not ours — for those samples VT lists only sandbox noise
(`169.254.169.254`, `224.0.0.251`, mDNS) or the bot's mass-scan targets, and in
one case (`b5b37d13…`) VT has only link-local while we extract
`181.214.99.180`, the very C2 VT confirms on a sibling sample. Real precision
is well above the 42% the arithmetic reports.

## Method note

Ghidra was driven through the MCP bridge against the live `miraitoushi`
project (`/home/thomas/miraitoushi`); imported programs need `run_analysis`
called twice before functions appear (first call returns
`total_functions: 1`). The `ghidra_project/` reps in this repo are the
headless read-only runs and carry no saved analysis.
