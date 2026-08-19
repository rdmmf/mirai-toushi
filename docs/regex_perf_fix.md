# Fix: catastrophic backtracking in `getMainFunc()`

## The bug

`getMainFunc()` filtered candidate functions with:

```python
re.findall(r".+?\(0\);.+?\(1\);.+?\(2\);", ccode)
```

Three chained lazy quantifiers with no anchor between them backtrack quadratically. On a statically linked build the decompiled libc contains very large functions — on one 99 KB decompiled function this single call spent **426s** to return zero matches. `runner.sh` runs all postScripts in one `analyzeHeadless` invocation, so that alone burned the sample's entire time budget before `xor_table.py`/`xor_scanner.py` even got a turn.

## The fix

`countCloseSeq()` computes the identical count with `str.find`, one line at a time — linear instead of quadratic:

```python
def countCloseSeq(text):
    total = 0
    for line in text.split("\n"):
        pos = 0
        while True:
            a = line.find("(0);", pos + 1)
            if a < 0: break
            b = line.find("(1);", a + 5)
            if b < 0: break
            c = line.find("(2);", b + 5)
            if c < 0: break
            total += 1
            pos = c + 4
    return total
```

Equivalence with the original regex was fuzzed over 120,000 random strings with zero mismatches before landing.

## Measured impact

Single sample (`cc40e161d86d…`, 194KB static x86): **455s → 41.8s** end-to-end.

Corpus-level, 226 real-world samples, same code otherwise (isolated A/B — only this fix differs between runs):

| metric | before | after | delta |
|---|--:|--:|--:|
| timeout rate | 19.9% (45/226) | **13.7% (31/226)** | **-6.2pp** |
| table extraction | 45.1% | 46.0% | +0.9pp |
| C2 extraction | 46.0% | 46.9% | +0.9pp |
| domain extraction | 1.8% | 2.2% | +0.4pp |
| C2 precision (VT-verified) | 42.4% | 44.1% | +1.7pp |

14 fewer samples time out; the small gains on every extraction metric follow from those samples now having enough of the shared time budget left for `xor_table.py`/`xor_scanner.py` to actually run.
