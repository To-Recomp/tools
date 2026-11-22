# sdk-identify

Names the Dolphin SDK functions of a stripped GameCube `main.dol` by comparing it with reference games whose decompilation projects published symbol maps.

Python 3 standard library only.

```
identify.py --target-dol main.dol --target-functions functions.txt --out-prefix GQSF \
    --reference ref1.dol ref1_symbols.txt ref1_splits.txt \
    --reference ref2.dol ref2_symbols.txt ref2_splits.txt
```

- `--reference`: the reference game's `main.dol` (from your own disc), its `symbols.txt` and `splits.txt` in the format of decomp-toolkit projects (for example `config/GZ2P01/` in `zeldaret/tp`, `config/GZLP01/` in `zeldaret/tww`, both CC0).
- `--target-functions`: one hexadecimal function start per line, for example from the gcrecomp control-flow analysis.
- Output: `<prefix>.csv` (`addr,name`, read by `gcrecomp_recompiler --csv`) and `<prefix>.matches.tsv` with the method, score, source file and whether the match is verified.

## Method

1. Each reference SDK function (those inside `dolphin/*` source units) becomes a signature: the instruction words with branch targets, immediates and load/store displacements masked out.
2. A target function is *exact* when its first words equal a signature. Otherwise it is *fuzzy*: the signature that shares the most 4-instruction n-grams, if the overlap is at least 0.6.
3. Matches are filtered to the heaviest chain that increases with the reference address, since the SDK is linked in the same source-file order in every game.
4. Between two consecutive anchors, if the target and the reference hold the same number of functions, they are paired in order (*layout*).
5. Several references are merged. The CSV keeps entries whose first four instructions equal the reference's, or that two references name identically.

## Limits

- It cannot name functions whose code changed between SDK builds or that are very short.
- A fuzzy match can land inside the real function. Treat names that are not in the CSV as unconfirmed.
- It identifies; it does not check behavior. Run the game before trusting a binding.

No game code is stored. The outputs are addresses and names.
