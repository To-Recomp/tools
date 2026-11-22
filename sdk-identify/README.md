# sdk-identify

Names the Dolphin SDK functions of a stripped GameCube `main.dol` by comparing it with reference games whose decompilation projects published symbol maps.

Python 3 standard library only (3.8 or later).

```
identify.py --target-dol main.dol --target-functions functions.txt --out-prefix GQSF \
    --reference ref1.dol ref1_symbols.txt ref1_splits.txt \
    --reference ref2.dol ref2_symbols.txt ref2_splits.txt \
    [--compare-with old.csv] [--truth names.csv] [--manual manual.csv]

identify.py --evaluate [--noise] --reference ... --reference ...
python3 -m unittest -v          # in this directory, synthetic data only
```

- `--reference`: the reference game's `main.dol` (from your own disc), its `symbols.txt` and `splits.txt` in the format of decomp-toolkit projects (for example `config/GZ2P01/` in `zeldaret/tp`, `config/GZLP01/` in `zeldaret/tww`, both CC0). Any number of references.
- `--target-functions`: one hexadecimal function start per line, for example from the gcrecomp control-flow analysis. The list may be noisy (see *Target functions*).
- Output:
  - `<prefix>.csv`: `addr,name`, read by `gcrecomp_recompiler --csv`.
  - `<prefix>.matches.tsv`: `address name method score start_ok agreed unit reference`.
  - `<prefix>.new.tsv` (with `--compare-with old.csv`): the CSV entries the old CSV lacks (`new`) or names differently (`renamed`), with the evidence (method, score, start verified, agreement, body lengths in words).
- `--truth names.csv`: names established independently (`addr,name`, comments after `#`). The run prints how many the result gets right, wrong, or leaves unnamed, for the merged result and for each reference alone.
- `--manual`: `addr,name  # evidence` lines that override automatic matches.
- `--evaluate`: held-out evaluation, see below.

## Method

1. **Target functions.** A control-flow analysis reports branch targets and prologue halves (`stwu` after `mflr; stw`) as function starts, and misses functions that only a pointer reaches (interrupt handlers, callbacks). The tool keeps a start when a `bl` calls it or when the previous word ends a function (`blr`, `bctr`, `b`), drops the others (they lie inside the previous function), and adds addresses that follow a function end and begin with `mflr r0` or `stwu r1`.
2. **Signatures.** Each reference SDK function (those inside `dolphin/*` source units, plus `OSReport` and `OSPanic`, which the decomp projects keep in the game's printf unit) becomes a masked body: branch targets, immediates and load/store displacements removed. A second, weaker form keeps only the opcode (register allocation differs between builds).
3. **Candidates.** *Exact*: the target's first words equal a reference body (at least 6 words). *Fuzzy*: the reference sharing most 4-word n-grams, overlap at least 0.6. *Version*: the init function of each module loads the `<< Dolphin SDK - X release build` string, in the target and in the reference.
4. **Anchors.** Candidates are reduced to chains that increase with the reference address, since functions are linked in source-file order. The order of whole *modules* is not stable (Tales of Symphonia links DSP, EXI and SI after GX; the references link EXI and SI right after OS and DSP before CARD), so several chains with disjoint spans in target and reference are kept; a chain replaces the anchors it overlaps when it outweighs them.
5. **Alignment.** Between two consecutive anchors, and at the open ends of a chain up to the end of its module, the unnamed target functions and reference functions are paired in order by an order-preserving alignment that maximises similarity (Dice coefficient of unigram+bigram multisets of the masked and opcode-only bodies, times a length factor; bodies of at most 3 words must be equal). Identical bodies are paired only when both sides hold as many copies. This is what names short functions, which no signature can.
6. **Call graph.** A matched function and its reference have the same call sites; the callee at each site gets the reference's callee name when the callee counts agree and the vote is repeated or the bodies are similar. A pair is vetoed when one of its callees is already firmly named (exact or version) as something else: this removes look-alike wrappers (`CARDWrite` vs `CARDDelete`).
7. **Layout.** If the same number of functions lies between two anchors on both sides and nothing matched, pair them in order. This is blind and never written to the CSV.
8. Several references are merged. The CSV keeps entries that two references name identically, or whose first instructions (at most four) equal the reference's and whose body is longer than two words, never a layout pairing.

## Evaluation

`--evaluate` hides each reference's names in turn, treats its DOL as the target (function starts taken from its symbol map; `--noise` also reports the second half of every prologue like a control-flow analysis does), and rebuilds the names from the other references. It prints, per SDK module and in total, the functions that another reference also has (*recoverable*), how many were found, how many names were given, how many are correct, and the same for the entries that would be written to the CSV; then precision per method.

This measures the matcher with correct starts. It does not measure the control-flow analysis, nor an SDK build that no reference resembles. `--truth` on the real target measures against a handful of names that were established by other means. `--compare-with` shows what changed against an earlier result.

## Limits

- It cannot name what the target does not contain: the linker removes unused functions (the target of the first results has no `OSMutex` or `OSMessage` function but `__OSUnlockAllMutex`).
- It cannot name a function that exists only in the target (`CARDDelete`, `CARDCheckAsync` are in no reference).
- An `align` or `fuzzy` name that is not in the CSV has no verified start and only one reference behind it.
- It identifies; it does not check behavior. Run the game before trusting a binding.

No game code is stored. The outputs are addresses and names.
