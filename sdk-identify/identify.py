#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Name the Dolphin SDK functions of a stripped GameCube main.dol.

Reference games whose decompilation projects published symbol maps (Twilight Princess and Wind Waker,
zeldaret/tp and zeldaret/tww, CC0) provide names and sizes. Each reference SDK function becomes a
masked signature (addresses and immediates removed). Functions of the target DOL are matched
against those signatures, then filtered and extended using the fact that the SDK is linked in the
same source-file order in every game. Several references are merged: the SDK changed between
builds, so a function missing from one reference is often unchanged in another.

The output holds names and addresses of the target only (facts, not code).

Usage:
  identify.py --target-dol main.dol --target-functions functions.txt --out-prefix GQSF \
      --reference ref1.dol ref1_symbols.txt ref1_splits.txt \
      --reference ref2.dol ref2_symbols.txt ref2_splits.txt
"""
import argparse
import bisect
import collections
import re
import struct
import sys

# Instruction fields that depend on where the code is linked or on the compiler's constants.
IMM_OPS = {7, 8, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29} | set(range(32, 56))
METHOD_RANK = {"exact": 3, "fuzzy": 2, "layout": 1}


def mask(word):
    op = word >> 26
    if op == 18:  # b / bl: drop the target
        return word & 0xFC000003
    if op == 16:  # bc: keep BO/BI, drop the displacement
        return word & 0xFFFF0003
    if op in IMM_OPS:  # immediates and load/store displacements
        return word & 0xFFFF0000
    return word


def masked(words):
    return tuple(mask(w) for w in words)


class Dol:
    def __init__(self, data):
        self.data = data
        offs = struct.unpack(">18I", data[:72])
        addrs = struct.unpack(">18I", data[0x48:0x90])
        sizes = struct.unpack(">18I", data[0x90:0xD8])
        self.sections = [(o, a, s) for o, a, s in zip(offs, addrs, sizes) if s]

    def words(self, addr, count):
        for o, a, s in self.sections:
            if a <= addr and addr + 4 * count <= a + s:
                start = o + addr - a
                return struct.unpack(">%dI" % count, self.data[start:start + 4 * count])
        return None


def parse_splits(path):
    """dolphin/* source units with their .text range."""
    units, cur = [], None
    for line in open(path):
        if re.match(r"^[^\s].*:\s*$", line) and not line.startswith("Sections"):
            cur = line.strip()[:-1]
        elif cur and ".text" in line and cur.startswith("dolphin/"):
            m = re.search(r"start:0x([0-9A-Fa-f]+) end:0x([0-9A-Fa-f]+)", line)
            if m:
                units.append((cur, int(m.group(1), 16), int(m.group(2), 16)))
    return units


def parse_symbols(path):
    out = []
    for line in open(path):
        m = re.match(r"^(\S+) = \.text:0x([0-9A-Fa-f]+); // type:function size:0x([0-9A-Fa-f]+)", line)
        if m:
            out.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
    return out


def grams(words, k=4):
    return {hash(words[i:i + k]) for i in range(max(0, len(words) - k + 1))}


def heaviest_chain(cands):
    """Heaviest chain increasing in reference address (cands sorted by target address)."""
    n = len(cands)
    best, prev = [0] * n, [-1] * n
    weight = lambda c: 3 if c["method"] == "exact" else 1
    for i in range(n):
        best[i] = weight(cands[i])
        for j in range(i):
            if cands[j]["ref"] < cands[i]["ref"] and best[j] + weight(cands[i]) > best[i]:
                best[i], prev[i] = best[j] + weight(cands[i]), j
    i = max(range(n), key=lambda k: best[k])
    chain = []
    while i >= 0:
        chain.append(cands[i])
        i = prev[i]
    return chain[::-1]


def match_reference(label, dol_path, symbols_path, splits_path, tgt, starts, min_exact, fuzzy_threshold):
    ref = Dol(open(dol_path, "rb").read())
    units = parse_splits(splits_path)

    def unit_of(addr):
        for name, start, end in units:
            if start <= addr < end:
                return name
        return None

    refs = []  # (name, unit, address, masked words)
    for name, addr, size in parse_symbols(symbols_path):
        unit = unit_of(addr)
        words = ref.words(addr, size // 4) if unit else None
        if words:
            refs.append((name, unit, addr, masked(words)))
    name_count = collections.Counter(r[0] for r in refs)
    ref_by_name = {r[0]: r for r in refs if name_count[r[0]] == 1}
    ref_words_by_addr = {r[2]: r[3] for r in refs}

    target_words = {}
    for i, a in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else a + 4
        w = tgt.words(a, min((end - a) // 4, 4000))
        if w:
            target_words[a] = masked(w)

    ref_grams = [grams(r[3]) for r in refs]
    inv = collections.defaultdict(list)
    for i, g in enumerate(ref_grams):
        for h in g:
            inv[h].append(i)
    common = {h for h, l in inv.items() if len(l) > 25}
    by_full = collections.defaultdict(list)
    for i, r in enumerate(refs):
        by_full[r[3]].append(i)
    lengths = sorted({len(r[3]) for r in refs})

    cands = []
    for a, words in target_words.items():
        exact = None
        for n in lengths:
            if min_exact <= n <= len(words) and words[:n] in by_full:
                exact = [refs[i][0] for i in by_full[words[:n]]]
        if exact:
            if len(set(exact)) == 1 and exact[0] in ref_by_name:
                r = ref_by_name[exact[0]]
                cands.append({"addr": a, "name": r[0], "unit": r[1], "ref": r[2], "method": "exact", "score": 1.0})
            continue
        if len(words) < 12:
            continue
        sg = grams(words) - common
        cnt = collections.Counter()
        for h in sg:
            for i in inv.get(h, ()):
                cnt[i] += 1
        if cnt:
            i, c = cnt.most_common(1)[0]
            denom = max(len(ref_grams[i] - common), len(sg))
            score = c / denom if denom else 0
            if score >= fuzzy_threshold and refs[i][0] in ref_by_name:
                r = refs[i]
                start = a
                k = bisect.bisect_left(starts, a)
                if words[:4] != r[3][:4]:
                    # The CFG may start a "function" inside the real one: look back a few starts.
                    for back in range(1, 4):
                        if k - back >= 0 and target_words.get(starts[k - back], ())[:4] == r[3][:4]:
                            start = starts[k - back]
                            break
                if start == a and k > 0:
                    # A start that follows code with no return or tail branch is inside that code:
                    # the function really begins at the previous start (within 64 bytes).
                    p = starts[k - 1]
                    pw = target_words.get(p, ())
                    between = pw[: (a - p) // 4]
                    if a - p <= 0x40 and between and not any(w in (0x4E800020, 0x4E800420) or (w & 0xFC000003) == 0x48000000 for w in between):
                        start = p
                cands.append({"addr": start, "name": r[0], "unit": r[1], "ref": r[2], "method": "fuzzy", "score": round(score, 2)})
    cands.sort(key=lambda c: c["addr"])
    chain = heaviest_chain(cands)
    result = {c["addr"]: c for c in chain}

    # Between two consecutive anchors, if the target and the reference hold the same number of
    # functions, pair them in order.
    ref_order = sorted((r[2], r[0], r[1]) for r in refs)
    ref_addrs = [r[0] for r in ref_order]
    for c1, c2 in zip(chain, chain[1:]):
        t_lo, t_hi = bisect.bisect_right(ref_addrs, c1["ref"]), bisect.bisect_left(ref_addrs, c2["ref"])
        s_lo, s_hi = bisect.bisect_right(starts, c1["addr"]), bisect.bisect_left(starts, c2["addr"])
        if t_hi > t_lo and t_hi - t_lo == s_hi - s_lo:
            for k in range(t_hi - t_lo):
                a = starts[s_lo + k]
                if a not in result:
                    ra, rn, ru = ref_order[t_lo + k]
                    result[a] = {"addr": a, "name": rn, "unit": ru, "ref": ra, "method": "layout", "score": 0.0}
    for c in result.values():
        c["reference"] = label
        # A name is only safe to bind when the function really starts here: the first
        # instructions must equal the reference's.
        c["start_ok"] = target_words.get(c["addr"], ())[:4] == ref_words_by_addr[c["ref"]][:4]
    print(f"[{label}] {len(refs)} reference functions -> {len(result)} named "
          f"{dict(collections.Counter(c['method'] for c in result.values()))}", file=sys.stderr)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", nargs=3, action="append", metavar=("DOL", "SYMBOLS", "SPLITS"), required=True)
    ap.add_argument("--target-dol", required=True)
    ap.add_argument("--target-functions", required=True, help="one hex function start per line")
    ap.add_argument("--out-prefix", required=True)
    ap.add_argument("--min-exact-words", type=int, default=6)
    ap.add_argument("--fuzzy-threshold", type=float, default=0.6)
    ap.add_argument("--manual", help="file of 'addr,name  # evidence' lines that override automatic matches")
    args = ap.parse_args()

    tgt = Dol(open(args.target_dol, "rb").read())
    starts = sorted(int(x.strip(), 16) for x in open(args.target_functions) if x.strip())

    per_ref = []
    for dol_path, sym_path, split_path in args.reference:
        per_ref.append(match_reference(dol_path.rsplit("/", 1)[-1], dol_path, sym_path, split_path, tgt, starts,
                                       args.min_exact_words, args.fuzzy_threshold))

    # Merge: best method wins; when two references disagree at the same address, the stronger
    # method wins and a tie is reported as a conflict and left unnamed.
    merged, conflicts = {}, []
    for result in per_ref:
        for a, c in result.items():
            cur = merged.get(a)
            if cur is None:
                merged[a] = c
                continue
            if cur["name"] == c["name"]:
                best = c if (METHOD_RANK[c["method"]], c["score"]) > (METHOD_RANK[cur["method"]], cur["score"]) else cur
                best["agreed"] = True  # two independent references name this address the same way
                best["start_ok"] = cur["start_ok"] or c["start_ok"]
                merged[a] = best
                continue
            rc, rn = (METHOD_RANK[c["method"]], c["score"]), (METHOD_RANK[cur["method"]], cur["score"])
            if rc > rn:
                merged[a] = c
            elif rc == rn:
                conflicts.append((a, cur["name"], c["name"]))
    for a, n1, n2 in conflicts:
        merged.pop(a, None)

    # Names established by hand from behavior (each line carries its evidence).
    if args.manual:
        for line in open(args.manual):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            addr_text, name = [x.strip() for x in line.split(",", 1)]
            a = int(addr_text, 16)
            merged[a] = {"addr": a, "name": name, "unit": "manual", "ref": 0, "method": "manual", "score": 1.0,
                         "start_ok": True, "agreed": True, "reference": "manual"}

    with open(args.out_prefix + ".csv", "w") as f:
        f.write("# Dolphin SDK function names for a stripped DOL, from tools/sdk-identify. addr,name\n")
        f.write("# Only entries whose start is verified (first instructions equal the reference's) or that two\n")
        f.write("# independent references name identically.\n")
        for a in sorted(merged):
            if merged[a]["start_ok"] or (merged[a].get("agreed") and merged[a]["method"] != "layout"):
                f.write(f"0x{a:08X},{merged[a]['name']}\n")
    with open(args.out_prefix + ".matches.tsv", "w") as f:
        f.write("address\tname\tmethod\tscore\tstart_ok\tagreed\tunit\treference\n")
        for a in sorted(merged):
            c = merged[a]
            f.write(f"0x{a:08X}\t{c['name']}\t{c['method']}\t{c['score']}\t{int(c['start_ok'])}\t{int(bool(c.get('agreed')))}\t{c['unit']}\t{c['reference']}\n")
    counts = collections.Counter(c["method"] for c in merged.values())
    ok = sum(c["start_ok"] for c in merged.values())
    print(f"merged: {len(merged)} functions named {dict(counts)}, {ok} with a verified start; {len(conflicts)} conflicts left unnamed", file=sys.stderr)


if __name__ == "__main__":
    main()
