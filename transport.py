"""TLS 1.3, CA/CRL validation, peer authorization and framed protocol records."""
import json
import socket
import ssl
import struct
import time

MAX_FRAME = 1024 * 1024
VERSION = "aopp-ad/1"


def tls_context(role, ca, cert, key, crl):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if role == "alice"
                         else ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca)
    ctx.load_verify_locations(cafile=crl)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF | ssl.VERIFY_X509_STRICT
    ctx.load_cert_chain(cert, key)
    ctx.options |= ssl.OP_NO_TICKET
    if role == "bob":
        ctx.num_tickets = 0
    return ctx


def authorize(sock, expected_dns):
    names = [value for kind, value in sock.getpeercert().get("subjectAltName", ())
             if kind == "DNS"]
    if expected_dns not in names:
        raise ValueError("Peer certificate does not contain the authorized DNS identity.")


class Channel:
    def __init__(self, sock, role, session):
        self.sock, self.role, self.session = sock, role, session
        self.sent = self.received = 0

    def send(self, kind, payload, round_id=0):
        record = dict(version=VERSION, session=self.session, sender=self.role,
                      sequence=self.sent, kind=kind, round=round_id,
                      expires=time.time() + 120, payload=payload)
        raw = json.dumps(record, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_FRAME:
            raise ValueError("Protocol frame too large.")
        self.sock.sendall(struct.pack("!I", len(raw)) + raw)
        self.sent += 1

    def _read(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.sock.recv(size - len(data))
            if not part:
                raise ConnectionError("Peer disconnected; discard this incomplete run.")
            data.extend(part)
        return data

    def receive(self, kind, round_id=0):
        size = struct.unpack("!I", self._read(4))[0]
        if not 0 < size <= MAX_FRAME:
            raise ValueError("Invalid protocol frame size.")
        msg = json.loads(self._read(size))
        peer = "bob" if self.role == "alice" else "alice"
        if not isinstance(msg, dict):
            raise ValueError("Invalid protocol record.")
        if (msg.get("version") != VERSION or msg.get("sender") != peer
                or msg.get("sequence") != self.received
                or msg.get("kind") != kind or msg.get("round") != round_id):
            raise ValueError("Unexpected protocol message or sequence.")
        expiry = msg.get("expires")
        if type(expiry) not in (int, float) or not time.time() <= expiry <= time.time() + 150:
            raise ValueError("Expired message or unsynchronized clocks.")
        session = msg.get("session")
        if not isinstance(session, str) or len(session) != 64:
            raise ValueError("Invalid session identifier.")
        if self.session is None:
            self.session = session
        if session != self.session:
            raise ValueError("Session mismatch.")
        self.received += 1
        return msg.get("payload")


def connect(ctx, host, port, peer, timeout):
    raw = socket.create_connection((host, port), timeout=timeout)
    secure = None
    try:
        secure = ctx.wrap_socket(raw, server_hostname=peer)
        authorize(secure, peer)
        return secure
    except Exception:
        if secure is not None:
            secure.close()
        raw.close()
        raise
