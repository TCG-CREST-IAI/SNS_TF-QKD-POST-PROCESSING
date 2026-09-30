"""Provision a dedicated local CA and separate endpoint bundles; never overwrite."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def provision(destination, alice_dns="alice.local", bob_dns="bob.local"):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AOPP AD Dedicated CA")])

    def builder(subject, public_key, days):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=days))
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False))

    ca = (builder(ca_name, ca_key.public_key(), 365)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
          .sign(ca_key, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca_name)
           .last_update(now-timedelta(minutes=5)).next_update(now+timedelta(days=30))
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
           .sign(ca_key, hashes.SHA256()))

    def write(path, data, private=False):
        path.write_bytes(data)
        if private:
            path.chmod(0o600)

    def key_bytes(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    authority = root / "authority"
    authority.mkdir()
    write(authority / "ca.key", key_bytes(ca_key), True)
    write(authority / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    for role, dns, usage in (("alice", alice_dns, ExtendedKeyUsageOID.CLIENT_AUTH),
                              ("bob", bob_dns, ExtendedKeyUsageOID.SERVER_AUTH)):
        folder = root / role
        folder.mkdir()
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
        cert = (builder(subject, key.public_key(), 30)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), False)
                .add_extension(x509.ExtendedKeyUsage([usage]), False)
                .sign(ca_key, hashes.SHA256()))
        write(folder / f"{role}.key", key_bytes(key), True)
        write(folder / f"{role}.pem", cert.public_bytes(serialization.Encoding.PEM))
        write(folder / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
        write(folder / "ca.crl.pem", crl.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="certs")
    parser.add_argument("--alice-dns", default="alice.local")
    parser.add_argument("--bob-dns", default="bob.local")
    args = parser.parse_args()
    provision(args.out, args.alice_dns, args.bob_dns)
    print(f"Created separate endpoint bundles in {args.out}. Keep authority/ offline.")
