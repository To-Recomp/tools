#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Name the Dolphin SDK functions of a stripped GameCube main.dol.

Reference games whose decompilation projects published symbol maps (Twilight Princess and Wind Waker,
zeldaret/tp and zeldaret/tww, CC0) provide names and sizes. Each reference SDK function becomes a
masked signature (addresses and immediates removed). Functions of the target DOL are matched
against those signatures, then constrained and extended using what stays true across SDK builds:

* the order of the functions inside a source file, and the order of the files inside a module,
* the call graph (a callee of a named function has the name of the reference's callee),
* the `<< Dolphin SDK - X release build` strings, referenced by the init function of module X.

The order of the *modules* is not stable (Tales of Symphonia links DSP, EXI and SI after GX, the
reference games link them before), so anchors are chosen as several chains, one per block.

The output holds names and addresses of the target only (facts, not code).

Usage:
  identify.py --target-dol main.dol --target-functions functions.txt --out-prefix GQSF \
      --reference ref1.dol ref1_symbols.txt ref1_splits.txt \
      --reference ref2.dol ref2_symbols.txt ref2_splits.txt [--truth names.csv]
  identify.py --evaluate --reference ... --reference ...      # hold each reference out in turn
"""
import argparse
import bisect
import collections
import re
import struct
import sys

# Instruction fields that depend on where the code is linked or on the compiler's constants.
IMM_OPS = {7, 8, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29} | set(range(32, 56))
METHOD_RANK = {"manual": 5, "version": 4, "exact": 3, "fuzzy": 2, "align": 2, "callgraph": 1, "layout": 0}
NOP = 0x60000000
RETURNS = (0x4E800020, 0x4E800420, 0x4C000064)  # blr, bctr, rfi
MAX_WORDS = 4000
# SDK functions that decompilation projects keep outside the dolphin/* source units (they sit in the
# game's own printf unit): matched by content alone, since their reference address says nothing about
# where the target links them.
FLOATING_SDK = {"OSReport": "dolphin/os/OSError.c", "OSPanic": "dolphin/os/OSError.c"}


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


def skeleton_word(word):
    """Opcode only (plus the extended opcode of the register forms): survives register allocation."""
    op = word >> 26
    if op in (31, 19):
        return word & 0xFC0007FE
    if op == 18 or op == 16:
        return word & 0xFC000001
    return word & 0xFC000000


def skeleton(words):
    return tuple(skeleton_word(w) for w in words)


def is_terminator(word):
    """The last word of a function body: blr, bctr, rfi or an unconditional branch."""
    return word in RETURNS or (word >> 26 == 18 and not word & 1)


def bl_target(addr, word):
    if word >> 26 == 18 and word & 3 == 1:
        li = word & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
        return (addr + li) & 0xFFFFFFFF
    return None


class Dol:
    def __init__(self, data):
        self.data = data
        offs = struct.unpack(">18I", data[:72])
        addrs = struct.unpack(">18I", data[0x48:0x90])
        sizes = struct.unpack(">18I", data[0x90:0xD8])
        self.sections = [(o, a, s) for o, a, s in zip(offs, addrs, sizes) if s]
        self.text = [(o, a, s) for o, a, s in zip(offs[:7], addrs[:7], sizes[:7]) if s]

    def words(self, addr, count):
        for o, a, s in self.sections:
            if a <= addr and addr + 4 * count <= a + s:
                start = o + addr - a
                return struct.unpack(">%dI" % count, self.data[start:start + 4 * count])
        return None

    def text_end(self, addr):
        """End of the text section holding addr."""
        for _, a, s in self.text:
            if a <= addr < a + s:
                return a + s
        return addr

    def in_text(self, addr):
        return any(a <= addr < a + s for _, a, s in self.text)

    def call_targets(self):
        """Every address that a bl in the text sections calls: these are real function starts."""
        out = set()
        for o, a, s in self.text:
            words = struct.unpack(">%dI" % (s // 4), self.data[o:o + s - s % 4])
            for i, w in enumerate(words):
                if w >> 26 == 18 and w & 3 == 1:
                    t = bl_target(a + 4 * i, w)
                    if self.in_text(t):
                        out.add(t)
        return out

    def prologue_starts(self):
        """Addresses right after a function end that begin like a function: `mflr r0` or `stwu r1`."""
        out = set()
        for o, a, s in self.text:
            words = struct.unpack(">%dI" % (s // 4), self.data[o:o + s - s % 4])
            for i, w in enumerate(words):
                if (w == 0x7C0802A6 or w >> 16 == 0x9421) and (i == 0 or words[i - 1] in (0, NOP) or is_terminator(words[i - 1])):
                    out.add(a + 4 * i)
        return out

    def addr_references(self, wanted):
        """{address: [code addresses]} for `lis rD,hi; addi rD,rD,lo` pairs that build a wanted address."""
        found = {}
        for o, a, s in self.text:
            words = struct.unpack(">%dI" % (s // 4), self.data[o:o + s - s % 4])
            pend = {}
            for i, x in enumerate(words):
                op = x >> 26
                if op == 15 and (x >> 16) & 31 == 0:
                    pend[(x >> 21) & 31] = (x & 0xFFFF, i)
                elif op == 14:
                    ra = (x >> 16) & 31
                    if ra in pend and i - pend[ra][1] < 12:
                        lo = x & 0xFFFF
                        lo -= (lo >> 15) << 16
                        ad = ((pend[ra][0] << 16) + lo) & 0xFFFFFFFF
                        if ad in wanted:
                            found.setdefault(ad, []).append(a + 4 * i)
        return found

    def version_strings(self):
        """{module: address} of the '<< Dolphin SDK - X release build' strings."""
        out = {}
        for m in re.finditer(rb"<< Dolphin SDK - (\w+)[\s]", self.data):
            for o, a, s in self.sections:
                if o <= m.start() < o + s:
                    out[m.group(1).decode()] = a + m.start() - o
        return out


def read_dol(path):
    with open(path, "rb") as f:
        return Dol(f.read())


def parse_splits(path):
    """dolphin/* source units with their .text range."""
    units, cur = [], None
    with open(path) as f:
        lines = f.read().splitlines()
    for line in lines:
        if re.match(r"^[^\s].*:\s*$", line) and not line.startswith("Sections"):
            cur = line.strip()[:-1]
        elif cur and ".text" in line and cur.startswith("dolphin/"):
            m = re.search(r"start:0x([0-9A-Fa-f]+) end:0x([0-9A-Fa-f]+)", line)
            if m:
                units.append((cur, int(m.group(1), 16), int(m.group(2), 16)))
    return units


def parse_symbols(path):
    out = []
    with open(path) as f:
        lines = f.read().splitlines()
    for line in lines:
        m = re.match(r"^(\S+) = \.text:0x([0-9A-Fa-f]+); // type:function size:0x([0-9A-Fa-f]+)", line)
        if m:
            out.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
    return out


def module_of(unit):
    parts = unit.split("/")
    return parts[1] if len(parts) > 2 else unit


class Func:
    """A function body and its fingerprints (full mask, opcode skeleton, n-gram multisets)."""

    def __init__(self, addr, words, name=None, unit=None):
        self.addr, self.words, self.name, self.unit = addr, tuple(words), name, unit
        self.m = masked(words)
        self.sk = skeleton(words)
        self._f = None
        self._calls = None

    @property
    def calls(self):
        if self._calls is None:
            self._calls = [t for i, w in enumerate(self.words) if (t := bl_target(self.addr + 4 * i, w)) is not None]
        return self._calls

    @property
    def feats(self):
        if self._f is None:
            self._f = (ngram_counts(self.m), ngram_counts(self.sk))
        return self._f


def ngram_counts(seq):
    c = collections.Counter(seq)
    c.update(zip(seq, seq[1:]))
    return c


def dice(a, b):
    inter = sum((a & b).values())
    return 2 * inter / (sum(a.values()) + sum(b.values()))


def similarity(t, r):
    """0..1 similarity of a target body and a reference body. Tiny bodies only match when equal."""
    lt, lr = len(t.m), len(r.m)
    lo, hi = min(lt, lr), max(lt, lr)
    if lo <= 3:
        if t.m == r.m:
            return 1.0
        return 0.8 if t.sk == r.sk else 0.0
    if hi > 2.5 * lo:
        return 0.0
    s = max(dice(t.feats[0], r.feats[0]), 0.85 * dice(t.feats[1], r.feats[1]))
    return s * (lo / hi) ** 0.5


def grams(words, k=4):
    return {hash(words[i:i + k]) for i in range(max(0, len(words) - k + 1))}


def start_ok(t, r):
    """The target begins like the reference: its first words (up to four) equal the reference's."""
    k = min(4, len(r.m))
    return len(t.m) >= k and t.m[:k] == r.m[:k]


class Reference:
    """The SDK functions of one reference game, with names."""

    def __init__(self, label, funcs):
        self.label = label
        self.funcs = sorted(funcs, key=lambda f: f.addr)
        self.addrs = [f.addr for f in self.funcs]
        count = collections.Counter(f.name for f in self.funcs)
        self.unique = {f.name: f for f in self.funcs if count[f.name] == 1}
        self.by_addr = {f.addr: f for f in self.funcs}
        self.grams = [grams(f.m) for f in self.funcs]
        self.inv = collections.defaultdict(list)
        for i, g in enumerate(self.grams):
            for h in g:
                self.inv[h].append(i)
        self.common = {h for h, lst in self.inv.items() if len(lst) > 25}
        self.by_full = collections.defaultdict(list)
        for i, f in enumerate(self.funcs):
            self.by_full[f.m].append(i)
        self.lengths = sorted({len(f.m) for f in self.funcs})
        self.index = {f.addr: i for i, f in enumerate(self.funcs)}
        self.version_funcs = {}  # module -> [Func] that reference its version string
        self.floating = []  # SDK functions outside the dolphin/* units: no usable position

    @classmethod
    def from_files(cls, dol_path, symbols_path, splits_path, label=None):
        dol = read_dol(dol_path)
        units = parse_splits(splits_path)
        spans = sorted((s, e, u) for u, s, e in units)
        starts = [s for s, _, _ in spans]

        def unit_of(addr):
            k = bisect.bisect_right(starts, addr) - 1
            return spans[k][2] if k >= 0 and addr < spans[k][1] else None

        funcs = []
        for name, addr, size in parse_symbols(symbols_path):
            unit = unit_of(addr)
            words = dol.words(addr, size // 4) if unit and size >= 4 else None
            if words:
                funcs.append(Func(addr, words, name, unit))
        ref = cls(label or dol_path.rsplit("/", 1)[-1], funcs)
        in_units = {f.addr for f in funcs}
        for name, addr, size in parse_symbols(symbols_path):
            words = dol.words(addr, size // 4) if size >= 4 else None
            if name in FLOATING_SDK and addr not in in_units and words:
                ref.floating.append(Func(addr, words, name, FLOATING_SDK[name]))
        refs = dol.addr_references(set(dol.version_strings().values()))
        by_str = {a: m for m, a in dol.version_strings().items()}
        for a, users in refs.items():
            for u in users:
                f = ref.containing(u)
                if f is not None and f not in ref.version_funcs.setdefault(by_str[a], []):
                    ref.version_funcs[by_str[a]].append(f)
        return ref

    def containing(self, addr):
        k = bisect.bisect_right(self.addrs, addr) - 1
        if k >= 0 and addr < self.addrs[k] + 4 * len(self.funcs[k].words):
            return self.funcs[k]
        return None


class Target:
    """The stripped DOL: function bodies rebuilt from a (possibly noisy) list of starts.

    A control-flow analysis reports branch targets and prologue halves as function starts, and misses
    functions that only a pointer reaches. A start is kept when something calls it, or when the previous
    word ends a function. Otherwise it lies inside the previous function and is dropped. Prologues
    that follow a function end are added.
    """

    def __init__(self, dol, starts):
        self.dol = dol
        self.calls = dol.call_targets()
        given = set(starts) | dol.prologue_starts()
        keep = []
        for a in sorted(given | self.calls):
            if a in self.calls:
                keep.append(a)
                continue
            prev = dol.words(a - 4, 1)
            if prev is None or is_terminator(prev[0]) or prev[0] in (0, NOP):
                keep.append(a)
        self.starts = keep
        self.funcs = []
        for i, a in enumerate(keep):
            end = keep[i + 1] if i + 1 < len(keep) else dol.text_end(a)
            words = dol.words(a, min(max((end - a) // 4, 1), MAX_WORDS))
            if not words:
                continue
            words = list(words)
            end_of_code = len(words)
            while end_of_code > 1 and words[end_of_code - 1] in (0, NOP):
                end_of_code -= 1
            if is_terminator(words[end_of_code - 1]):
                del words[end_of_code:]
            self.funcs.append(Func(a, words))
        self.addrs = [f.addr for f in self.funcs]
        self.by_addr = {f.addr: f for f in self.funcs}
        self.index = {f.addr: i for i, f in enumerate(self.funcs)}

    def containing(self, addr):
        k = bisect.bisect_right(self.addrs, addr) - 1
        return self.funcs[k] if k >= 0 else None


def heaviest_chain(cands):
    """Heaviest chain increasing in reference address (cands sorted by target address)."""
    n = len(cands)
    if not n:
        return []
    best, prev = [0] * n, [-1] * n
    for i in range(n):
        wi = cands[i]["weight"]
        best[i] = wi
        for j in range(i):
            if cands[j]["ref"] < cands[i]["ref"] and best[j] + wi > best[i]:
                best[i], prev[i] = best[j] + wi, j
    i = max(range(n), key=lambda k: best[k])
    chain = []
    while i >= 0:
        chain.append(cands[i])
        i = prev[i]
    return chain[::-1]


def select_chains(cands, min_weight=3):
    """Several chains with disjoint spans (in target and in reference address).

    The SDK is linked in the same file order in every game, but the order of whole modules can
    differ (DSP, EXI and SI come after GX in Tales of Symphonia). A single increasing chain would
    drop the moved block, so each further chain is accepted when it outweighs the anchors it
    overlaps; those anchors are dropped.
    """
    remaining = sorted(cands, key=lambda c: c["addr"])
    accepted = []
    while remaining:
        chain = heaviest_chain(remaining)
        w = sum(c["weight"] for c in chain)
        ids = {id(c) for c in chain}
        remaining = [c for c in remaining if id(c) not in ids]
        if accepted and w < min_weight:
            break
        lo_t, hi_t = chain[0]["addr"], chain[-1]["addr"]
        lo_r, hi_r = min(c["ref"] for c in chain), max(c["ref"] for c in chain)
        conflicts = [c for ch in accepted for c in ch if lo_t <= c["addr"] <= hi_t or lo_r <= c["ref"] <= hi_r]
        if conflicts:
            if sum(c["weight"] for c in conflicts) >= w:
                continue
            cid = {id(c) for c in conflicts}
            accepted = [[c for c in ch if id(c) not in cid] for ch in accepted]
        accepted.append(chain)
    return [ch for ch in accepted if ch]


def align_window(tfuncs, rfuncs, threshold, veto=None):
    """Order-preserving pairing that maximises the summed similarity (weighted LCS).

    `veto(t, r)` rules a pair out (for example because their callees are already known to differ)."""
    n, m = len(tfuncs), len(rfuncs)
    sim = [[0.0] * m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            s = similarity(tfuncs[i], rfuncs[j])
            sim[i][j] = s if s >= threshold and not (veto and veto(tfuncs[i], rfuncs[j])) else 0.0
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            dp[i][j] = max(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1] + sim[i - 1][j - 1] if sim[i - 1][j - 1] else 0.0)
    pairs, i, j = [], n, m
    while i > 0 and j > 0:
        s = sim[i - 1][j - 1]
        if s and dp[i][j] == dp[i - 1][j - 1] + s:
            pairs.append((i - 1, j - 1, s))
            i, j = i - 1, j - 1
        elif dp[i][j] == dp[i - 1][j]:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    # Identical bodies cannot be told apart by content: keep them only when both sides hold as
    # many copies, so that the order decides.
    tcount = collections.Counter(f.m for f in tfuncs)
    rcount = collections.Counter(f.m for f in rfuncs)
    return [(i, j, s) for i, j, s in pairs
            if tcount[tfuncs[i].m] == rcount[rfuncs[j].m] or (tcount[tfuncs[i].m] == 1 and rcount[rfuncs[j].m] == 1)]


class Matcher:
    def __init__(self, ref, tgt, min_exact=6, fuzzy_threshold=0.6, align_threshold=0.6):
        self.ref, self.tgt = ref, tgt
        self.min_exact, self.fuzzy_threshold, self.align_threshold = min_exact, fuzzy_threshold, align_threshold
        self.result = {}  # target addr -> candidate

    # -- candidates ---------------------------------------------------------------------------
    def candidates(self):
        ref, cands = self.ref, []
        for t in self.tgt.funcs:
            words = t.m
            exact = None
            for n in ref.lengths:
                if self.min_exact <= n <= len(words) and words[:n] in ref.by_full:
                    exact = [ref.funcs[i].name for i in ref.by_full[words[:n]]]
                    pick = ref.by_full[words[:n]][0]
            if exact:
                if len(set(exact)) == 1 and exact[0] in ref.unique:
                    r = ref.funcs[pick]
                    cands.append(self.cand(t, r, "exact", 1.0, 3))
                continue
            if len(words) < 12:
                continue
            sg = grams(words) - ref.common
            cnt = collections.Counter()
            for h in sg:
                for i in ref.inv.get(h, ()):
                    cnt[i] += 1
            if cnt:
                i, c = cnt.most_common(1)[0]
                denom = max(len(ref.grams[i] - ref.common), len(sg))
                score = c / denom if denom else 0
                if score >= self.fuzzy_threshold and ref.funcs[i].name in ref.unique:
                    cands.append(self.cand(t, ref.funcs[i], "fuzzy", round(score, 2), 1))
        return cands

    def version_anchors(self):
        """The init function of each module references the module's version string in both builds."""
        dol = self.tgt.dol
        strings = dol.version_strings()
        refs = dol.addr_references(set(strings.values()))
        out = []
        for module, a in strings.items():
            tf = []
            for u in refs.get(a, ()):
                f = self.tgt.containing(u)
                if f is not None and f not in tf:
                    tf.append(f)
            rf = self.ref.version_funcs.get(module, [])
            if tf and len(tf) == len(rf):
                for t, r in zip(tf, rf):
                    if r.name in self.ref.unique:
                        out.append(self.cand(t, r, "version", 1.0, 4))
        return out

    def cand(self, t, r, method, score, weight):
        return {"addr": t.addr, "name": r.name, "unit": r.unit, "ref": r.addr, "method": method,
                "score": score, "weight": weight}

    # -- gap filling --------------------------------------------------------------------------
    def assigned(self):
        return sorted(self.result.values(), key=lambda c: c["addr"])

    def add(self, c):
        self.result[c["addr"]] = c

    def windows(self, chains):
        """(target funcs, reference funcs) strictly between consecutive anchors of a chain, plus the
        open ends of each chain, bounded by the module of the end anchor."""
        ref, tgt = self.ref, self.tgt
        out = []
        all_t = sorted(self.result)
        for chain in chains:
            chain = [c for c in chain if c["addr"] in self.result]
            for c1, c2 in zip(chain, chain[1:]):
                out.append(((tgt.index[c1["addr"]] + 1, tgt.index[c2["addr"]]),
                            (ref.index[c1["ref"]] + 1, ref.index[c2["ref"]])))
            if not chain:
                continue
            # Open ends: up to as many target functions as the module has reference functions left.
            first, last = chain[0], chain[-1]
            mod = module_of(last["unit"])
            rj = ref.index[last["ref"]] + 1
            rk = rj
            while rk < len(ref.funcs) and module_of(ref.funcs[rk].unit) == mod:
                rk += 1
            ti = tgt.index[last["addr"]] + 1
            nxt = bisect.bisect_right(all_t, last["addr"])
            tk = tgt.index[all_t[nxt]] if nxt < len(all_t) else len(tgt.funcs)
            tk = min(tk, ti + 2 * (rk - rj))
            if rk > rj and tk > ti:
                out.append(((ti, tk), (rj, rk)))
            mod = module_of(first["unit"])
            rk = ref.index[first["ref"]]
            rj = rk
            while rj > 0 and module_of(ref.funcs[rj - 1].unit) == mod:
                rj -= 1
            tk = tgt.index[first["addr"]]
            prv = bisect.bisect_left(all_t, first["addr"]) - 1
            ti = tgt.index[all_t[prv]] + 1 if prv >= 0 else 0
            ti = max(ti, tk - 2 * (rk - rj))
            if rk > rj and tk > ti:
                out.append(((ti, tk), (rj, rk)))
        return out

    def strong_maps(self):
        strong = [c for c in self.result.values() if c["method"] in ("exact", "version")]
        return {c["ref"]: c["addr"] for c in strong}, {c["addr"]: c["ref"] for c in strong}

    def callee_conflicts(self, t, r, maps=None):
        """Call sites where both callees are firmly named but not as each other: t cannot be r."""
        by_ref, by_tgt = maps or self.strong_maps()
        if len(t.calls) != len(r.calls):
            return 0
        return sum(1 for tc, rc in zip(t.calls, r.calls)
                   if (rc in by_ref and by_ref[rc] != tc) or (tc in by_tgt and by_tgt[tc] != rc))

    def prune(self):
        """Drop weak names whose callees contradict firmly named ones."""
        maps = self.strong_maps()
        for a in [a for a, c in self.result.items() if c["method"] not in ("exact", "version")]:
            c = self.result[a]
            if self.callee_conflicts(self.tgt.by_addr[a], self.ref.by_addr[c["ref"]], maps):
                del self.result[a]

    def fill_windows(self, chains, method="align"):
        added = 0
        maps = self.strong_maps()
        veto = lambda t, r: self.callee_conflicts(t, r, maps) > 0
        for (ti, tk), (rj, rk) in self.windows(chains):
            if tk <= ti or rk <= rj or (tk - ti) * (rk - rj) > 60000:
                continue
            tf = [f for f in self.tgt.funcs[ti:tk] if f.addr not in self.result]
            rf = [f for f in self.ref.funcs[rj:rk] if f.addr not in {c["ref"] for c in self.result.values()}]
            for i, j, s in align_window(tf, rf, self.align_threshold, veto):
                if rf[j].name in self.ref.unique:
                    self.add(self.cand(tf[i], rf[j], method, round(s, 2), 1))
                    added += 1
        return added

    def propagate_calls(self):
        """A callee of a matched function takes the name of the reference's callee at the same call site."""
        ref, tgt = self.ref, self.tgt
        votes = collections.defaultdict(int)
        for c in list(self.result.values()):
            t, r = tgt.by_addr.get(c["addr"]), ref.by_addr.get(c["ref"])
            if t is None or r is None or len(t.calls) != len(r.calls):
                continue
            for tc, rc in zip(t.calls, r.calls):
                if tc in tgt.by_addr and rc in ref.by_addr and ref.by_addr[rc].name in ref.unique and tc != c["addr"]:
                    votes[(tc, rc)] += 1
        used_ref = {c["ref"] for c in self.result.values()}
        ranked = []
        for (tc, rc), v in votes.items():
            if tc in self.result or rc in used_ref:
                continue
            s = similarity(tgt.by_addr[tc], ref.by_addr[rc])
            if (v >= 2 or s >= 0.5) and not self.callee_conflicts(tgt.by_addr[tc], ref.by_addr[rc]):
                ranked.append((v, s, tc, rc))
        ranked.sort(reverse=True)
        added = 0
        for v, s, tc, rc in ranked:
            if tc in self.result or rc in used_ref:
                continue
            if not self.order_consistent(tc, rc):
                continue
            self.add(self.cand(tgt.by_addr[tc], ref.by_addr[rc], "callgraph", round(max(s, 0.0), 2), 1))
            used_ref.add(rc)
            added += 1
        return added

    def order_consistent(self, tc, rc):
        """Inserting (tc, rc) keeps the neighbouring anchors in order."""
        a = self.assigned()
        addrs = [c["addr"] for c in a]
        k = bisect.bisect_left(addrs, tc)
        lo = a[k - 1]["ref"] if k > 0 else None
        hi = a[k]["ref"] if k < len(a) else None
        if lo is not None and hi is not None and lo > hi:
            return True  # a block boundary: neighbours belong to different blocks
        return (lo is None or rc > lo) and (hi is None or rc < hi) or self.block_boundary(a, k, rc)

    def block_boundary(self, a, k, rc):
        """The neighbours are in other modules than the reference function: the block order differs."""
        mod = module_of(self.ref.by_addr[rc].unit)
        near = [x for x in (a[k - 1] if k > 0 else None, a[k] if k < len(a) else None) if x]
        return bool(near) and all(module_of(x["unit"]) != mod for x in near)

    def edge_consistency(self):
        """{method: (agree, total)}: at each call site of a named function whose callee is also named, does
        the callee carry the name of the reference's callee? Independent of how the names were found,
        except for the call-graph step, which is excluded."""
        out = collections.defaultdict(lambda: [0, 0])
        for a, c in self.result.items():
            t, r = self.tgt.by_addr[a], self.ref.by_addr.get(c["ref"])
            if r is None or len(t.calls) != len(r.calls):
                continue
            for tc, rc in zip(t.calls, r.calls):
                n = self.result.get(tc)
                if n is None or rc not in self.ref.by_addr or "callgraph" in (c["method"], n["method"]):
                    continue
                out[c["method"]][1] += 1
                out[c["method"]][0] += n["name"] == self.ref.by_addr[rc].name
        return out

    def layout(self):
        """Equal numbers of unnamed functions between two named ones in the same module: pair in order."""
        ref, tgt = self.ref, self.tgt
        a = self.assigned()
        added = 0
        for c1, c2 in zip(a, a[1:]):
            if not c1["ref"] < c2["ref"]:
                continue
            ri, rk = ref.index[c1["ref"]] + 1, ref.index[c2["ref"]]
            ti, tk = tgt.index[c1["addr"]] + 1, tgt.index[c2["addr"]]
            if rk > ri and rk - ri == tk - ti:
                for d in range(rk - ri):
                    f, r = tgt.funcs[ti + d], ref.funcs[ri + d]
                    if f.addr not in self.result and r.name in ref.unique:
                        self.add(self.cand(f, r, "layout", 0.0, 0))
                        added += 1
        return added

    def place_floating(self):
        """Match the position-free SDK functions on content: the best body must be clearly better than the next."""
        out, used = {}, set(self.result)
        for r in self.ref.floating:
            scored = sorted(((similarity(t, r), t.addr) for t in self.tgt.funcs
                             if t.addr not in used and 0.5 * len(r.m) <= len(t.m) <= 2 * len(r.m)), reverse=True)[:2]
            if scored and scored[0][0] >= self.fuzzy_threshold and (len(scored) < 2 or scored[0][0] - scored[1][0] >= 0.1):
                s, a = scored[0]
                c = self.cand(self.tgt.by_addr[a], r, "exact" if s == 1.0 else "fuzzy", round(s, 2), 1)
                c["reference"] = self.ref.label
                c["start_ok"] = start_ok(self.tgt.by_addr[a], r)
                c["short"] = False
                c["twords"], c["rwords"] = len(self.tgt.by_addr[a].m), len(r.m)
                out[a] = c
                used.add(a)
        return out

    def run(self):
        cands = self.candidates() + self.version_anchors()
        chains = select_chains(cands)
        for ch in chains:
            for c in ch:
                self.add(c)
        for _ in range(3):
            n = self.fill_windows(chains) + self.propagate_calls()
            chains = self.rechain()
            if not n:
                break
        self.layout()
        self.prune()
        for c in self.result.values():
            c["reference"] = self.ref.label
            t, r = self.tgt.by_addr[c["addr"]], self.ref.by_addr[c["ref"]]
            c["start_ok"] = start_ok(t, r)
            c["short"] = min(len(t.m), len(r.m)) < 3
            c["twords"], c["rwords"] = len(t.m), len(r.m)
        for a, c in self.place_floating().items():
            self.result[a] = c
        return self.result

    def rechain(self):
        """Consecutive anchors in target order, split where the reference order jumps (a block boundary)."""
        chains, cur = [], []
        for c in self.assigned():
            if cur and c["ref"] < cur[-1]["ref"]:
                chains.append(cur)
                cur = []
            cur.append(c)
        if cur:
            chains.append(cur)
        return chains


def merge_references(per_ref):
    """Best method wins; two references that name an address alike set `agreed`; a tie between
    different names is a conflict and the address stays unnamed."""
    merged, conflicts = {}, []
    for result in per_ref:
        for a, c in result.items():
            cur = merged.get(a)
            if cur is None:
                merged[a] = dict(c)
                continue
            if cur["name"] == c["name"]:
                best = dict(c if (METHOD_RANK[c["method"]], c["score"]) > (METHOD_RANK[cur["method"]], cur["score"]) else cur)
                best["agreed"] = True
                best["start_ok"] = cur["start_ok"] or c["start_ok"]
                best["reference"] = cur["reference"] + "+" + c["reference"]
                merged[a] = best
                continue
            rc, rn = (METHOD_RANK[c["method"]], c["score"]), (METHOD_RANK[cur["method"]], cur["score"])
            if rc > rn:
                merged[a] = dict(c)
            elif rc == rn:
                conflicts.append(a)
    for a in conflicts:
        merged.pop(a, None)
    return merged, conflicts


def in_csv(c):
    """Names that are safe to bind: a verified start (not a one-instruction body), or two references agree."""
    if c["method"] == "manual":
        return True
    if c.get("agreed") and c["method"] != "layout":
        return True
    return bool(c["start_ok"]) and not c.get("short") and c["method"] != "layout"


def read_truth(path):
    out = {}
    with open(path) as f:
        lines = f.read().splitlines()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            a, n = [x.strip() for x in line.split(",", 1)]
            out[int(a, 16)] = n
    return out


def score_against(named, truth):
    right = sum(1 for a, n in truth.items() if named.get(a) == n)
    wrong = {a: (n, named[a]) for a, n in truth.items() if a in named and named[a] != n}
    return right, wrong, sum(1 for a in truth if a not in named)


# -- evaluation: hide a reference's names, rebuild them from the others --------------------------
def pseudo_target(dol_path, symbols_path, noise=False):
    dol = read_dol(dol_path)
    syms = parse_symbols(symbols_path)
    starts = [a for _, a, _ in syms]
    if noise:  # mimic a control-flow analysis that also reports the second half of a prologue
        starts += [a + 8 for _, a, s in syms if s > 16 and (dol.words(a, 1) or (0,))[0] == 0x7C0802A6]
    return dol, starts, syms


def evaluate(reference_args, noise, min_exact, fuzzy_threshold, align_threshold):
    refs = [Reference.from_files(*r) for r in reference_args]
    rows = collections.defaultdict(lambda: collections.Counter())
    total = collections.Counter()
    for k, args in enumerate(reference_args):
        dol, starts, syms = pseudo_target(args[0], args[1], noise)
        held = refs[k]
        others = [r for i, r in enumerate(refs) if i != k]
        truth = {f.addr: f.name for f in held.funcs if f.name in held.unique}
        unit = {f.addr: module_of(f.unit) for f in held.funcs}
        for f in held.floating:
            truth[f.addr], unit[f.addr] = f.name, module_of(f.unit)
        recoverable = {a for a, n in truth.items() if any(n in o.unique or any(n == x.name for x in o.floating) for o in others)}
        tgt = Target(dol, starts)
        for o in others:
            res = Matcher(o, tgt, min_exact, fuzzy_threshold, align_threshold).run()
            for a, c in res.items():
                mod = unit.get(a, "(not sdk)")
                ok = truth.get(a) == c["name"]
                for key in (mod, "ALL"):
                    rows[key]["named"] += 1
                    rows[key]["correct" if ok else "wrong"] += 1
                    rows[key]["by_" + c["method"] + ("_ok" if ok else "_bad")] += 1
                    if in_csv(c):
                        rows[key]["csv"] += 1
                        rows[key]["csv_ok" if ok else "csv_bad"] += 1
                    if ok and a in recoverable:
                        rows[key]["found"] += 1
            for a in recoverable:
                for key in (unit[a], "ALL"):
                    rows[key]["recoverable"] += 1
            print(f"held out {held.label}, reference {o.label}: {len(res)} named", file=sys.stderr)
    return rows


def print_eval(rows, out=sys.stdout):
    out.write("module\trecoverable\tfound\trecall\tnamed\tcorrect\twrong\tprecision\tcsv\tcsv_bad\tcsv_precision\n")
    for key in sorted(rows, key=lambda k: (k == "ALL", k)):
        r = rows[key]
        rec = r["found"] / r["recoverable"] if r["recoverable"] else float("nan")
        pre = r["correct"] / r["named"] if r["named"] else float("nan")
        cp = r["csv_ok"] / r["csv"] if r["csv"] else float("nan")
        out.write(f"{key}\t{r['recoverable']}\t{r['found']}\t{rec:.3f}\t{r['named']}\t{r['correct']}\t{r['wrong']}\t{pre:.3f}\t{r['csv']}\t{r['csv_bad']}\t{cp:.3f}\n")


def write_new(path, merged, old):
    """Entries of the new CSV that an earlier CSV lacks (new) or names differently (renamed), with their evidence."""
    with open(path, "w") as f:
        f.write("address\tname\tstatus\told_name\tmethod\tscore\tstart_ok\tagreed\twords_target\twords_reference"
                "\tunit\treference\n")
        for a in sorted(merged):
            c = merged[a]
            if not in_csv(c) or old.get(a) == c["name"]:
                continue
            f.write(f"0x{a:08X}\t{c['name']}\t{'renamed' if a in old else 'new'}\t{old.get(a, '')}\t{c['method']}\t"
                    f"{c['score']}\t{int(c['start_ok'])}\t{int(bool(c.get('agreed')))}\t{c.get('twords', '')}\t"
                    f"{c.get('rwords', '')}\t{c['unit']}\t{c['reference']}\n")


def print_methods(rows, out=sys.stdout):
    out.write("\nmethod\tnamed\tcorrect\tprecision\n")
    for m in sorted(METHOD_RANK, key=METHOD_RANK.get, reverse=True):
        ok, bad = rows["ALL"]["by_%s_ok" % m], rows["ALL"]["by_%s_bad" % m]
        if ok + bad:
            out.write(f"{m}\t{ok + bad}\t{ok}\t{ok / (ok + bad):.3f}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", nargs=3, action="append", metavar=("DOL", "SYMBOLS", "SPLITS"), required=True)
    ap.add_argument("--target-dol")
    ap.add_argument("--target-functions", help="one hex function start per line")
    ap.add_argument("--out-prefix")
    ap.add_argument("--min-exact-words", type=int, default=6)
    ap.add_argument("--fuzzy-threshold", type=float, default=0.6)
    ap.add_argument("--align-threshold", type=float, default=0.6)
    ap.add_argument("--manual", help="file of 'addr,name  # evidence' lines that override automatic matches")
    ap.add_argument("--compare-with", metavar="CSV",
                    help="an earlier CSV: also write <prefix>.new.tsv with the entries it lacks or names differently")
    ap.add_argument("--truth", help="file of 'addr,name' lines known independently: reports precision on them")
    ap.add_argument("--evaluate", action="store_true",
                    help="hide each reference's names in turn and rebuild them from the others")
    ap.add_argument("--noise", action="store_true", help="with --evaluate: add fragment starts like a CFG does")
    args = ap.parse_args()

    if args.evaluate:
        rows = evaluate(args.reference, args.noise, args.min_exact_words, args.fuzzy_threshold, args.align_threshold)
        print_eval(rows)
        print_methods(rows)
        return
    if not (args.target_dol and args.target_functions and args.out_prefix):
        ap.error("--target-dol, --target-functions and --out-prefix are required unless --evaluate")

    with open(args.target_functions) as f:
        starts = [int(x.strip(), 16) for x in f if x.strip()]
    tgt = Target(read_dol(args.target_dol), starts)
    print(f"target: {len(tgt.funcs)} function bodies", file=sys.stderr)
    per_ref = []
    for r in args.reference:
        ref = Reference.from_files(*r)
        matcher = Matcher(ref, tgt, args.min_exact_words, args.fuzzy_threshold, args.align_threshold)
        res = matcher.run()
        print(f"[{ref.label}] {len(ref.funcs)} reference functions -> {len(res)} named "
              f"{dict(collections.Counter(c['method'] for c in res.values()))}", file=sys.stderr)
        per_ref.append(res)
        edges = matcher.edge_consistency()
        print(f"[{ref.label}] call-site agreement by method: "
              + ", ".join(f"{m} {a}/{n}" for m, (a, n) in sorted(edges.items())), file=sys.stderr)
    merged, conflicts = merge_references(per_ref)

    # Names established by hand from behavior (each line carries its evidence).
    if args.manual:
        for a, name in read_truth(args.manual).items():
            merged[a] = {"addr": a, "name": name, "unit": "manual", "ref": 0, "method": "manual", "score": 1.0,
                         "start_ok": True, "agreed": True, "reference": "manual"}

    with open(args.out_prefix + ".csv", "w") as f:
        f.write("# Dolphin SDK function names for a stripped DOL, from tools/sdk-identify. addr,name\n")
        f.write("# Only entries whose start is verified (first instructions equal the reference's) or that two\n")
        f.write("# independent references name identically.\n")
        for a in sorted(merged):
            if in_csv(merged[a]):
                f.write(f"0x{a:08X},{merged[a]['name']}\n")
    with open(args.out_prefix + ".matches.tsv", "w") as f:
        f.write("address\tname\tmethod\tscore\tstart_ok\tagreed\tunit\treference\n")
        for a in sorted(merged):
            c = merged[a]
            f.write(f"0x{a:08X}\t{c['name']}\t{c['method']}\t{c['score']}\t{int(c['start_ok'])}\t{int(bool(c.get('agreed')))}\t{c['unit']}\t{c['reference']}\n")
    if args.compare_with:
        write_new(args.out_prefix + ".new.tsv", merged, read_truth(args.compare_with))
    counts = collections.Counter(c["method"] for c in merged.values())
    ok = sum(c["start_ok"] for c in merged.values())
    csv_n = sum(in_csv(c) for c in merged.values())
    print(f"merged: {len(merged)} functions named {dict(counts)}, {ok} with a verified start, {csv_n} in the CSV; "
          f"{len(conflicts)} conflicts left unnamed", file=sys.stderr)
    agreed = [a for a, c in merged.items() if c.get("agreed")]
    both = [a for a in set.intersection(*[set(r) for r in per_ref])] if len(per_ref) > 1 else []
    same = sum(1 for a in both if len({r[a]["name"] for r in per_ref}) == 1)
    if both:
        print(f"references agree on {same} of the {len(both)} addresses they all name ({100.0 * same / len(both):.1f}%)",
              file=sys.stderr)
    if args.truth:
        truth = read_truth(args.truth)
        named = {a: c["name"] for a, c in merged.items()}
        right, wrong, missing = score_against(named, truth)
        print(f"truth: {right} right, {len(wrong)} wrong, {missing} unnamed of {len(truth)}; wrong: "
              f"{ {hex(a): v for a, v in wrong.items()} }", file=sys.stderr)
        for k, r in enumerate(per_ref):
            right, wrong, missing = score_against({a: c["name"] for a, c in r.items()}, truth)
            print(f"truth, {args.reference[k][0].rsplit('/', 1)[-1]} alone: {right} right, {len(wrong)} wrong, "
                  f"{missing} unnamed", file=sys.stderr)
    print(f"{len(agreed)} entries named by two references", file=sys.stderr)


if __name__ == "__main__":
    main()
