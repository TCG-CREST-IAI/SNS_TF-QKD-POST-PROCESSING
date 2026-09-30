import itertools
import unittest
from algorithms import accept_block, active_pairs, masked_block, odd_parity, parse_bits


class AlgorithmTests(unittest.TestCase):
    def test_input(self):
        self.assertEqual(parse_bits("\ufeff01 \n10\t"), "0110")
        self.assertEqual(parse_bits(" \n"), "")
        for bad in ("012", "０１", "0,1"):
            with self.assertRaises(ValueError):
                parse_bits(bad)

    def test_pairing_invariants(self):
        for bits in ("", "0", "111", "01010", "01"*1000):
            pairs = active_pairs(bits)
            indices = [index for pair in pairs for index in pair]
            self.assertEqual(len(pairs), min(bits.count("0"), bits.count("1")))
            self.assertEqual(len(indices), len(set(indices)))
            self.assertTrue(all(odd_parity(bits, pair) for pair in pairs))

    def test_report_aopp_table(self):
        for alice, expected in (("01", True), ("00", False), ("11", False), ("10", True)):
            self.assertEqual(odd_parity(alice, (0, 1)), expected)

    def test_ad_exhaustive(self):
        for size in range(1, 5):
            strings = ["".join(x) for x in itertools.product("01", repeat=size)]
            for alice in strings:
                for bob in strings:
                    expected = len({a != b for a, b in zip(alice, bob)}) == 1
                    for mask in (0, 1):
                        message = "".join(str(int(b) ^ mask) for b in alice)
                        self.assertEqual(accept_block(bob, message), expected)
            self.assertTrue(all(c in "01" for c in masked_block(strings[0])))


if __name__ == "__main__":
    unittest.main()
