# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests on synthetic code: no game data is needed. Run: python3 -m unittest -v (in this directory)."""
import os
import random
import struct
import tempfile
import unittest

import identify as I

BASE = 0x80003100
MFLR, STWU, MTLR, ADDI_SP, BLR = 0x7C0802A6, 0x9421FFF0, 0x7C0803A6, 0x38210010, 0x4E800020


# add, subf, and, or, xor, mullw, divw, slw, srw, nor: X/XO-form words with distinct extended opcodes
FORMS = [0x7C000214, 0x7C000050, 0x7C000038, 0x7C000378, 0x7C000278, 0x7C0001D6, 0x7C0003D6, 0x7C000030,
         0x7C000430, 0x7C0000F8]


def add(rd, ra, rb):
    return 0x7C000214 | rd << 21 | ra << 16 | rb << 11


def bl(src, dst):
    return 0x48000001 | ((dst - src) & 0x03FFFFFC)


def body(seed, n=10, calls=()):
    """A prologue, n register-form arithmetic words (distinct per seed), optional calls, an epilogue."""
    rnd = random.Random(seed)
    words = [MFLR, STWU]
    words += [rnd.choice(FORMS) | rnd.randrange(32) << 21 | rnd.randrange(32) << 16 | rnd.randrange(32) << 11
              for _ in range(n)]
    words += [("call", c) for c in calls]
    return words + [MTLR, ADDI_SP, BLR]


def link(funcs, base=BASE):
    """funcs: list of (name, words); returns (code words, {name: address}). Calls are ("call", name)."""
    addrs, a = {}, base
    for name, words in funcs:
        addrs[name] = a
        a += 4 * len(words)
    out, a = [], base
    for name, words in funcs:
        for w in words:
            if isinstance(w, tuple):
                w = bl(a, addrs[w[1]])
            out.append(w)
            a += 4
    return out, addrs


def make_dol(code, base=BASE, data=None, data_addr=0x80300000):
    """A DOL with one text section (and an optional data section)."""
    text = struct.pack(">%dI" % len(code), *code)
    offs, addrs, sizes = [0] * 18, [0] * 18, [0] * 18
    offs[0], addrs[0], sizes[0] = 0x100, base, len(text)
    blob = text
    if data is not None:
        offs[7], addrs[7], sizes[7] = 0x100 + len(text), data_addr, len(data)
        blob += data
    head = struct.pack(">18I", *offs) + struct.pack(">18I", *addrs) + struct.pack(">18I", *sizes)
    return I.Dol(head.ljust(0x100, b"\0") + blob)


def write_dol(path, dol):
    with open(path, "wb") as f:
        f.write(dol.data)


def write_reference(tmp, funcs, units, base=BASE):
    """Writes symbols/splits files for linked funcs; units: [(unit, first func name, last func name)]."""
    code, addrs = link(funcs, base)
    dol = make_dol(code, base)
    sizes = {n: 4 * len(w) for n, w in funcs}
    sym = os.path.join(tmp, "sym.txt")
    spl = os.path.join(tmp, "spl.txt")
    with open(sym, "w") as f:
        for n, _ in funcs:
            f.write(f"{n} = .text:0x{addrs[n]:08X}; // type:function size:0x{sizes[n]:X} scope:global align:4\n")
    with open(spl, "w") as f:
        f.write("Sections:\n\t.text type:code align:4\n\n")
        for unit, first, last in units:
            f.write(f"{unit}:\n\t.text       start:0x{addrs[first]:08X} end:0x{addrs[last] + sizes[last]:08X}\n\n")
    return dol, sym, spl, addrs


class MaskTests(unittest.TestCase):
    def test_branch_target_and_immediates_are_masked_registers_are_kept(self):
        self.assertEqual(I.mask(bl(0x80003100, 0x80004000)), 0x48000001)
        self.assertEqual(I.mask(0x38610020), 0x38610000)  # addi r3,r1,0x20
        self.assertEqual(I.mask(0x80630008), 0x80630000)  # lwz r3,8(r3)
        self.assertEqual(I.mask(0x41820040), 0x41820000)  # beq +0x40
        self.assertEqual(I.mask(add(3, 4, 5)), add(3, 4, 5))
        self.assertEqual(I.mask(BLR), BLR)

    def test_skeleton_ignores_registers(self):
        self.assertEqual(I.skeleton_word(add(3, 4, 5)), I.skeleton_word(add(9, 8, 7)))
        self.assertNotEqual(I.skeleton_word(add(3, 4, 5)), I.skeleton_word(0x7C000050))  # subf

    def test_terminators_and_call_targets(self):
        self.assertTrue(I.is_terminator(BLR))
        self.assertTrue(I.is_terminator(0x48000010))  # b
        self.assertFalse(I.is_terminator(bl(0, 8)))
        self.assertFalse(I.is_terminator(MFLR))
        self.assertEqual(I.bl_target(0x80003100, bl(0x80003100, 0x80003000)), 0x80003000)
        self.assertIsNone(I.bl_target(0x80003100, 0x48000010))


class SimilarityTests(unittest.TestCase):
    def test_equal_and_register_renamed_bodies(self):
        a = I.Func(0, body(1))
        self.assertEqual(I.similarity(a, I.Func(4, body(1))), 1.0)
        other = I.Func(8, body(2))
        self.assertLess(I.similarity(a, other), 0.6)
        # Same operations on other registers: the masked words differ, the skeletons do not.
        regs = [w ^ (0x1F << 21) if w >> 26 == 31 else w for w in body(1)]
        self.assertGreater(I.similarity(a, I.Func(0, regs)), 0.8)

    def test_tiny_bodies_match_only_when_equal_or_same_skeleton(self):
        getter = I.Func(0, [0x806D8000, BLR])
        self.assertEqual(I.similarity(getter, I.Func(8, [0x806D9000, BLR])), 1.0)  # immediate differs only
        self.assertEqual(I.similarity(getter, I.Func(8, [0x80ED8000, BLR])), 0.8)  # other register, same shape
        self.assertEqual(I.similarity(getter, I.Func(8, [0x906D8000, BLR])), 0.0)  # store, not load

    def test_start_ok_uses_at_most_the_first_four_words_and_needs_the_target_to_be_that_long(self):
        r = I.Func(0, body(1))
        self.assertTrue(I.start_ok(I.Func(0, body(1)), r))
        self.assertFalse(I.start_ok(I.Func(0, body(2)), r))
        self.assertTrue(I.start_ok(I.Func(0, [BLR, BLR]), I.Func(0, [BLR])))
        self.assertFalse(I.start_ok(I.Func(0, [BLR]), I.Func(0, [BLR, BLR])))


class TargetTests(unittest.TestCase):
    def test_fragment_starts_are_dropped_and_missing_starts_found(self):
        funcs = [("a", body(1)), ("b", body(2, calls=["a"])), ("c", body(3))]
        code, addrs = link(funcs)
        dol = make_dol(code)
        # The analysis reports a's second half (a fragment) and misses c entirely (nothing calls it).
        tgt = I.Target(dol, [addrs["a"], addrs["a"] + 8, addrs["b"]])
        self.assertIn(addrs["a"], tgt.by_addr)
        self.assertNotIn(addrs["a"] + 8, tgt.by_addr)  # follows non-terminator code: inside a
        self.assertIn(addrs["c"], tgt.by_addr)  # follows a blr and begins with a prologue, though nothing lists it
        self.assertEqual(len(tgt.by_addr[addrs["a"]].words), len(funcs[0][1]))

    def test_call_targets_are_function_starts(self):
        funcs = [("a", [0x806D8000, BLR]), ("b", body(2, calls=["a"]))]
        code, addrs = link(funcs)
        tgt = I.Target(make_dol(code), [addrs["b"]])
        self.assertIn(addrs["a"], tgt.by_addr)

    def test_trailing_padding_is_trimmed(self):
        code = body(1) + [0, 0] + body(2)
        tgt = I.Target(make_dol(code), [BASE, BASE + 4 * (len(body(1)) + 2)])
        self.assertEqual(len(tgt.by_addr[BASE].words), len(body(1)))

    def test_version_string_users_are_found(self):
        data = b"<< Dolphin SDK - XYZ\trelease build: Apr 17 2003 >>\0"
        addr = 0x80300000
        init = [0x3C600000 | addr >> 16, 0x38630000 | addr & 0xFFFF, BLR]  # lis r3,hi; addi r3,r3,lo
        dol = make_dol(init, data=data, data_addr=addr)
        self.assertEqual(dol.version_strings(), {"XYZ": addr})
        self.assertEqual(dol.addr_references({addr}), {addr: [BASE + 4]})


class ChainTests(unittest.TestCase):
    @staticmethod
    def cand(addr, ref, weight=3):
        return {"addr": addr, "ref": ref, "weight": weight}

    def test_heaviest_chain_drops_the_out_of_order_light_candidate(self):
        c = [self.cand(10, 100), self.cand(20, 50, 1), self.cand(30, 110), self.cand(40, 120)]
        self.assertEqual([x["addr"] for x in I.heaviest_chain(c)], [10, 30, 40])

    def test_a_moved_block_becomes_its_own_chain(self):
        # Reference order: block 1 (refs 100-300), block 2 (refs 400-600). The target links 2 before 1.
        c = [self.cand(1000 + i, 400 + 10 * i) for i in range(4)] + [self.cand(2000 + i, 100 + 10 * i) for i in range(4)]
        chains = I.select_chains(c)
        self.assertEqual(sorted(len(ch) for ch in chains), [4, 4])

    def test_a_heavy_block_removes_a_lone_spurious_anchor_inside_its_span(self):
        c = [self.cand(1000 + i, 100 + 10 * i) for i in range(5)]
        c.append(self.cand(5000, 125, 1))  # lone fuzzy anchor that lands among the heavy chain's refs
        chains = I.select_chains(c)
        self.assertEqual(sum(len(ch) for ch in chains), 5)


class AlignTests(unittest.TestCase):
    def test_unequal_counts_are_paired_by_content_in_order(self):
        refs = [I.Func(100 + 64 * i, body(i, 10 + i)) for i in range(5)]
        tgts = [I.Func(900 + 64 * i, body(i, 10 + i)) for i in (0, 2, 3, 4)]  # function 1 was dropped
        pairs = I.align_window(tgts, refs, 0.6)
        self.assertEqual([(i, j) for i, j, _ in pairs], [(0, 0), (1, 2), (2, 3), (3, 4)])

    def test_identical_bodies_are_kept_only_when_the_counts_agree(self):
        blr = lambda a: I.Func(a, [BLR])
        self.assertEqual(len(I.align_window([blr(0), blr(4)], [blr(100), blr(104)], 0.6)), 2)
        self.assertEqual(I.align_window([blr(0)], [blr(100), blr(104)], 0.6), [])

    def test_veto_removes_a_pair(self):
        refs = [I.Func(100, body(1))]
        tgts = [I.Func(900, body(1))]
        self.assertEqual(I.align_window(tgts, refs, 0.6, veto=lambda t, r: True), [])


class MatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def reference(self):
        # Two units. Unit B holds a short wrapper that calls its sibling; unit A is OS-like.
        funcs = [("A1", body(1, 12)), ("A2", body(2, 14)), ("A3", [0x806D8000, BLR]), ("A4", body(4, 9, ["A1"])),
                 ("B1", body(5, 20)), ("B2", body(6, 16)), ("B3", body(7, 11, ["B1"]))]
        return write_reference(self.tmp.name, funcs, [("dolphin/os/OS.c", "A1", "A4"), ("dolphin/exi/EXI.c", "B1", "B3")])

    def target_dol(self, order):
        bodies = {"A1": body(1, 12), "A2": body(2, 15), "A3": [0x806D8004, BLR], "A4": body(4, 9, ["A1"]),
                  "B1": body(5, 20), "B2": body(6, 17), "B3": body(7, 11, ["B1"])}
        pad = body(99, 5)
        funcs = []
        for n in order:
            funcs.append((n, bodies[n]))
            funcs.append(("pad" + n, pad))
        code, addrs = link(funcs)
        return make_dol(code), addrs

    def test_modules_in_swapped_order_are_found_and_changed_bodies_still_match(self):
        dol, sym, spl, _ = self.reference()
        refpath = os.path.join(self.tmp.name, "ref.dol")
        write_dol(refpath, dol)
        ref = I.Reference.from_files(refpath, sym, spl)
        tgt_dol, addrs = self.target_dol(["B1", "B2", "B3", "A1", "A2", "A3", "A4"])
        tgt = I.Target(tgt_dol, list(addrs.values()))
        res = I.Matcher(ref, tgt).run()
        named = {a: c["name"] for a, c in res.items()}
        for n in ("A1", "A2", "A3", "A4", "B1", "B2", "B3"):
            self.assertEqual(named.get(addrs[n]), n, n)
        self.assertEqual(res[addrs["A1"]]["method"], "exact")
        self.assertNotIn(res[addrs["A2"]]["method"], ("exact",))  # one word longer than the reference
        self.assertFalse(any(c["name"].startswith("pad") for c in res.values()))

    def test_edge_consistency_is_reported(self):
        dol, sym, spl, _ = self.reference()
        refpath = os.path.join(self.tmp.name, "ref.dol")
        write_dol(refpath, dol)
        ref = I.Reference.from_files(refpath, sym, spl)
        tgt_dol, addrs = self.target_dol(["A1", "A2", "A3", "A4", "B1", "B2", "B3"])
        m = I.Matcher(ref, I.Target(tgt_dol, []))
        m.run()
        agree, total = m.edge_consistency()["exact"]
        self.assertGreater(total, 0)
        self.assertEqual(agree, total)

    def test_call_graph_veto_blocks_a_lookalike_wrapper(self):
        """A wrapper that calls a function named differently than the reference's callee is not that wrapper."""
        refs_funcs = [("Async", body(1, 30)), ("Wrap", body(2, 3, ["Async"])), ("Other", body(9, 4))]
        dol, sym, spl, _ = write_reference(self.tmp.name, refs_funcs, [("dolphin/card/C.c", "Async", "Other")])
        refpath = os.path.join(self.tmp.name, "ref.dol")
        write_dol(refpath, dol)
        ref = I.Reference.from_files(refpath, sym, spl)
        # Target: Async present, then another async-like function X and a wrapper of X; Wrap itself is absent.
        funcs = [("Async", body(1, 30)), ("X", body(5, 30)), ("XWrap", body(2, 4, ["X"])), ("Other", body(9, 4))]
        code, addrs = link(funcs)
        m = I.Matcher(ref, I.Target(make_dol(code), []))
        res = m.run()
        self.assertEqual(res[addrs["Async"]]["name"], "Async")
        self.assertNotIn(addrs["XWrap"], res)

    def test_layout_pairs_equal_counts_between_anchors(self):
        refs_funcs = [("F1", body(1, 20)), ("F2", body(2, 7)), ("F3", body(3, 7)), ("F4", body(4, 20))]
        dol, sym, spl, _ = write_reference(self.tmp.name, refs_funcs, [("dolphin/os/OS.c", "F1", "F4")])
        refpath = os.path.join(self.tmp.name, "ref.dol")
        write_dol(refpath, dol)
        ref = I.Reference.from_files(refpath, sym, spl)
        funcs = [("F1", body(1, 20)), ("G2", body(12, 30)), ("G3", body(13, 31)), ("F4", body(4, 20))]
        code, addrs = link(funcs)
        res = I.Matcher(ref, I.Target(make_dol(code), [])).run()
        self.assertEqual(res[addrs["G2"]]["name"], "F2")
        self.assertEqual(res[addrs["G2"]]["method"], "layout")
        self.assertEqual(res[addrs["G3"]]["name"], "F3")
        self.assertFalse(I.in_csv(res[addrs["G2"]]))  # a blind pairing is never written to the CSV


class MergeTests(unittest.TestCase):
    @staticmethod
    def c(name, method, score=1.0, ok=True, ref="r"):
        return {"name": name, "method": method, "score": score, "start_ok": ok, "reference": ref}

    def test_agreement_and_stronger_method_and_ties(self):
        a = {1: self.c("X", "fuzzy", 0.7, False, "a"), 2: self.c("Y", "exact", 1.0, True, "a"), 3: self.c("Z", "align", 0.7, False, "a")}
        b = {1: self.c("X", "exact", 1.0, True, "b"), 2: self.c("W", "layout", 0.0, True, "b"), 3: self.c("V", "fuzzy", 0.7, False, "b")}
        merged, conflicts = I.merge_references([a, b])
        self.assertTrue(merged[1]["agreed"])
        self.assertEqual(merged[1]["method"], "exact")
        self.assertEqual(merged[2]["name"], "Y")  # exact beats layout
        self.assertNotIn(3, merged)  # equal strength, different names: left unnamed
        self.assertEqual(conflicts, [3])

    def test_csv_rule(self):
        self.assertTrue(I.in_csv(self.c("X", "exact")))
        self.assertFalse(I.in_csv(self.c("X", "fuzzy", ok=False)))  # start not verified, one reference
        self.assertTrue(I.in_csv(dict(self.c("X", "fuzzy", ok=False), agreed=True)))
        self.assertFalse(I.in_csv(dict(self.c("X", "layout"), agreed=True)))
        self.assertFalse(I.in_csv(dict(self.c("X", "exact"), short=True)))  # a one-word body begins like anything
        self.assertTrue(I.in_csv(dict(self.c("X", "exact"), short=True, agreed=True)))

    def test_truth_scoring(self):
        right, wrong, missing = I.score_against({1: "A", 2: "B"}, {1: "A", 2: "C", 3: "D"})
        self.assertEqual((right, wrong, missing), (1, {2: ("C", "B")}, 1))


if __name__ == "__main__":
    unittest.main()
