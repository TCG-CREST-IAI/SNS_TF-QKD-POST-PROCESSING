import json
import socket
import struct
import time
import unittest
from transport import Channel, MAX_FRAME, VERSION


class TransportTests(unittest.TestCase):
    def test_reject_wrong_metadata_and_expiry(self):
        good = dict(version=VERSION, session="a"*64, sender="bob", sequence=0,
                    kind="test", round=0, expires=time.time()+120, payload={})
        for field, bad in (("version", "old"), ("session", "b"*64), ("sender", "alice"),
                           ("sequence", 1), ("kind", "other"), ("round", 1),
                           ("expires", time.time()-1)):
            with self.subTest(field=field):
                left, right = socket.socketpair()
                with left, right:
                    message = dict(good, **{field:bad})
                    raw = json.dumps(message).encode()
                    right.sendall(struct.pack("!I", len(raw))+raw)
                    with self.assertRaises(ValueError):
                        Channel(left, "alice", "a"*64).receive("test")

    def test_reject_oversized_frame_before_payload(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(struct.pack("!I", MAX_FRAME+1))
            with self.assertRaises(ValueError):
                Channel(left, "alice", "a"*64).receive("test")

    def test_replayed_sequence(self):
        left, right = socket.socketpair()
        with left, right:
            sender, receiver = Channel(right, "bob", "a"*64), Channel(left, "alice", "a"*64)
            sender.send("test", {})
            receiver.receive("test")
            sender.sent = 0
            sender.send("test", {})
            with self.assertRaises(ValueError):
                receiver.receive("test")
