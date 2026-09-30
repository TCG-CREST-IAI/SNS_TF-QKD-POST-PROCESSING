import queue
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from certificates import provision
import alice
import bob
from transport import authorize, tls_context, connect


class MTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name) / "certs"
        provision(cls.root)
        cls.other = Path(cls.temp.name) / "other"
        provision(cls.other)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def config(self, role, root=None):
        folder = (root or self.root) / role
        return dict(host="127.0.0.1", port=0, timeout=5,
                    peer="bob.local" if role == "alice" else "alice.local",
                    ca=str(folder / "ca.pem"), crl=str(folder / "ca.crl.pem"),
                    cert=str(folder / f"{role}.pem"), key=str(folder / f"{role}.key"))

    def test_real_distributed_functions_all_modes(self):
        for mode in ("AOPP", "AD", "AOPP+AD"):
            ready, result = queue.Queue(), queue.Queue()
            def serve():
                try:
                    result.put(bob.process("01101001"*10, mode, 2, self.config("bob"), ready.put))
                except Exception as error:
                    result.put(error)
            thread = threading.Thread(target=serve)
            thread.start()
            config = self.config("alice")
            config["port"] = ready.get(timeout=5)
            client_result = alice.process("01101001"*10, mode, 2, config)
            thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(client_result, result.get(timeout=1))

    def handshake(self, client_config, server_config=None, no_client_cert=False):
        server_config = server_config or self.config("bob")
        ctx = tls_context("bob", **{k:server_config[k] for k in ("ca", "cert", "key", "crl")})
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        errors = []
        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(5)
                        with ctx.wrap_socket(raw, server_side=True) as sock:
                            authorize(sock, server_config["peer"])
                            sock.sendall(b"ok")
            except Exception as error:
                errors.append(error)
        port = listener.getsockname()[1]
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            if no_client_cert:
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client.load_verify_locations(cafile=client_config["ca"])
                client.minimum_version = ssl.TLSVersion.TLSv1_3
            else:
                client = tls_context("alice", **{k:client_config[k] for k in ("ca", "cert", "key", "crl")})
            with connect(client, "127.0.0.1", port, client_config["peer"], 5) as sock:
                if sock.recv(2) != b"ok":
                    errors.append(ConnectionError("Rejected"))
        except Exception as error:
            errors.append(error)
        thread.join(10)
        self.assertFalse(thread.is_alive())
        return errors

    def test_valid_certificates(self):
        self.assertFalse(self.handshake(self.config("alice")))

    def test_missing_client_certificate(self):
        self.assertTrue(self.handshake(self.config("alice"), no_client_cert=True))

    def test_untrusted_ca(self):
        self.assertTrue(self.handshake(self.config("alice", self.other)))

    def test_wrong_server_identity(self):
        config = self.config("alice")
        config["peer"] = "wrong.local"
        self.assertTrue(self.handshake(config))

    def test_wrong_authorized_client_identity(self):
        config = self.config("bob")
        config["peer"] = "other-alice.local"
        self.assertTrue(self.handshake(self.config("alice"), config))

    def test_wrong_client_role(self):
        config = self.config("alice")
        config.update(cert=self.config("bob")["cert"], key=self.config("bob")["key"])
        self.assertTrue(self.handshake(config))

    def test_revoked_client(self):
        ca = x509.load_pem_x509_certificate((self.root / "authority/ca.pem").read_bytes())
        key = serialization.load_pem_private_key((self.root / "authority/ca.key").read_bytes(), None)
        cert = x509.load_pem_x509_certificate((self.root / "alice/alice.pem").read_bytes())
        now = datetime.now(timezone.utc)
        revoked = x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(now-timedelta(minutes=1)).build()
        crl = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
               .last_update(now-timedelta(minutes=1)).next_update(now+timedelta(days=1))
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
               .add_revoked_certificate(revoked).sign(key, hashes.SHA256()))
        path = Path(self.temp.name) / "revoked.pem"
        path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        config = self.config("bob")
        config["crl"] = str(path)
        errors = self.handshake(self.config("alice"), config)
        self.assertTrue(any("revoked" in str(error).lower() for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
