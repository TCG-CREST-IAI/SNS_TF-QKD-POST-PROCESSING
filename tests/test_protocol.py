import socket
import threading
import unittest
from protocol import run
from transport import Channel


def pair_run(alice, bob, mode, block=2, bob_mode=None):
    left, right = socket.socketpair()
    left.settimeout(5)
    right.settimeout(5)
    results, errors = {}, []
    def execute(role, sock, bits, selected):
        try:
            with sock:
                results[role] = run(Channel(sock, role, "a"*64 if role == "alice" else None), bits, selected, block)
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=execute, args=("bob", right, bob, bob_mode or mode))
    thread.start()
    execute("alice", left, alice, mode)
    thread.join(10)
    if thread.is_alive():
        raise AssertionError("Protocol deadlock")
    return results, errors


class ProtocolTests(unittest.TestCase):
    def test_identical_inputs_all_modes_and_edge_lengths(self):
        for mode in ("AOPP", "AD", "AOPP+AD"):
            for bits in ("", "0", "11111", "01", "0101101010110", "01"*1200):
                result, errors = pair_run(bits, bits, mode)
                self.assertFalse(errors, errors)
                self.assertEqual(result["alice"], result["bob"])

    def test_ad_keep_first_and_drop_tail(self):
        result, errors = pair_run("0011010", "0000101", "AD")
        self.assertFalse(errors)
        self.assertEqual(result["alice"]["bits"], "010")
        self.assertEqual(result["bob"]["bits"], "001")
        self.assertEqual(result["alice"]["stages"][0]["discarded_tail"], 1)

    def test_all_flips_survive(self):
        for mode in ("AOPP", "AD", "AOPP+AD"):
            result, errors = pair_run("01"*20, "10"*20, mode)
            self.assertFalse(errors)
            self.assertTrue(result["alice"]["bits"])
            self.assertTrue(all(a != b for a, b in zip(result["alice"]["bits"], result["bob"]["bits"])))

    def test_mismatch_fails(self):
        for args in (("0", "00", "AD"), ("01", "01", "AD", 2, "AOPP")):
            results, errors = pair_run(*args)
            self.assertFalse(results)
            self.assertEqual(len(errors), 2)

    def test_large_ad_block_across_chunks(self):
        result, errors = pair_run("0"*70001, "0"*70001, "AD", 70000)
        self.assertFalse(errors)
        self.assertEqual(result["alice"]["bits"], "0")
        result, errors = pair_run("0"*70000, "0"*32768+"1"*37232, "AD", 70000)
        self.assertFalse(errors)
        self.assertEqual(result["alice"]["bits"], "")


if __name__ == "__main__":
    unittest.main()
