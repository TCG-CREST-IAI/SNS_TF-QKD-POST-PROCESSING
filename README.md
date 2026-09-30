# AOPP and AD over authenticated mTLS

Two independent Streamlit applications process corresponding Alice and Bob bitstrings. Each server receives only its own input, either pasted text or a UTF-8 `.txt` file. Both applications offer **AOPP**, **AD**, and **AOPP+AD**. Alice connects to Bob through a persistent, mutually authenticated TLS 1.3 connection.

## Install

Use Python 3.10 or newer with OpenSSL supporting TLS 1.3. Copy this project to both servers and run these commands in the project directory:

```sh
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```sh
# Linux / macOS
source .venv/bin/activate
```

Then install:

```sh
python -m pip install -r requirements.txt
```

## Certificates and distribution

On a trusted provisioning machine, create a dedicated CA and two distinct identities:

```sh
python certificates.py --out certs --alice-dns alice.local --bob-dns bob.local
```

The command refuses to overwrite an existing directory. It creates:

```text
certs/
  authority/  ca.pem, ca.key
  alice/      ca.pem, ca.crl.pem, alice.pem, alice.key
  bob/        ca.pem, ca.crl.pem, bob.pem, bob.key
```

Transfer **only `certs/alice/` to Alice's server** and **only `certs/bob/` to Bob's server**, through your trusted deployment channel. Keep `authority/` offline; neither endpoint needs the CA private key or the other endpoint's private key. Restrict key-file access to the application account; on Windows apply account-specific NTFS permissions (POSIX `chmod` does not provide Windows ACL isolation).

The supplied provisioning helper creates a private CA for a working deployment, with 30-day endpoint certificates and a 30-day empty signed CRL. It does not confer external organizational certification. For an operational installation, use your managed dedicated CA to issue and rotate certificates and publish updated signed CRLs. Replace each endpoint's CRL before it expires and whenever a certificate is revoked. Missing, expired, or invalid CRLs cause validation to fail closed. Do not renew a CRL by silently removing existing revocations.

Externally issued certificates must contain a DNS Subject Alternative Name matching the configured peer identity, correct key usages, and `clientAuth` EKU for Alice or `serverAuth` EKU for Bob. Supply PEM certificate chains where needed, a trusted CA bundle, and the appropriate issuer's PEM CRL. The helper's defaults are device identities: they do not require DNS resolution when Alice connects using Bob's IP address. For real hostnames, pass your names to the helper and set the expected peer identities accordingly.

## Run on two servers

On Bob's server:

```sh
python -m streamlit run bob.py --server.port 8502
```

On Alice's server:

```sh
python -m streamlit run alice.py --server.port 8501
```

Open Bob's UI at `http://127.0.0.1:8502` on Bob's machine and Alice's at `http://127.0.0.1:8501` on Alice's machine. The UI binds to loopback by default. To operate a remote server from your workstation, use an SSH tunnel, for example `ssh -L 8502:127.0.0.1:8502 user@bob-server`, and browse the local forwarded port. Use the corresponding port 8501 for Alice. This protects browser input separately from the Alice–Bob mTLS channel.

1. In Bob's sidebar, choose the listen address (`0.0.0.0` for all IPv4 interfaces), protocol port (default `8443`), expected Alice certificate identity, and local certificate paths.
2. In Alice's sidebar, enter Bob's reachable IP address or hostname and the same protocol port. Set the expected Bob certificate identity. The network address and certificate identity are separate settings.
3. Choose the same operation on both sides. For AD, choose the same block size. Use the same block-size setting for AOPP too, since all settings are checked before processing.
4. Each party selects **Text** or **Text file** and enters its own input. The selected source is authoritative; text and file contents are never concatenated.
5. Click **Listen and process** on Bob, then **Connect and process** on Alice before the wait expires.
6. Each UI displays its own processed bits, stage counts, and a download button. Only the first 4,096 output bits are previewed; downloads contain the entire output.

Permit TCP traffic from Alice to Bob's protocol port in your server firewall. Synchronize server clocks for certificate and message validity checks. Run one operator/session per endpoint process. Bob listens for one run per button click, then closes the listener. Rejected TLS clients do not consume the run; Bob continues waiting within the original timeout. A disconnect or failed run is discarded; start a new run on both sides. There is no persistent job store or automatic resume. Completion counts confirm protocol progress, not equality of the retained keys; a final network failure can leave only one side aware of completion, so discard that run on both endpoints.

Sidebar defaults can be set using `QKD_HOST`, `QKD_PORT`, `QKD_PEER`, `QKD_CA`, `QKD_CRL`, `QKD_CERT`, and `QKD_KEY`. Paths are resolved on the server running that application.

## Inputs and size handling

- Input consists of `0` and `1`; whitespace and an initial UTF-8 BOM are ignored. Other characters are rejected. File inputs must decode as UTF-8.
- Both inputs must already be sifted, aligned bitstrings using the intended SNS bit conventions. No detector filtering, SNS remapping, padding, or truncation is silently applied.
- Corresponding input lengths must match. Empty inputs, one-bit inputs, odd lengths, and strings with only one bit value are supported, including a valid empty output.
- There is no fixed algorithmic bit-length limit. Inputs and AOPP index lists are held in memory, so practical capacity depends on RAM and browser limits. Streamlit's file-upload limit is configured to 200 MB; change `server.maxUploadSize` in `.streamlit/config.toml` if needed. Large inputs should use files. The implementation is not an out-of-core processor.
- AOPP sends at most 512 pairs per message. AD sends chunks of at most 32,768 masked bits, even when a block is larger. Transport frames are bounded at 1 MiB, independent of total input length. Very small AD blocks incur more network round trips.

## Algorithms and report correspondence

Reference: *Progress Report: Post-Processing in Sending-or-Not-Sending Twin-Field Quantum Key Distribution*, Nilesh Ganguly and Mohammad Bin Aftab, September 29, 2026 (`sns_tf_qkd_post_processing_report.pdf`, supplied with the request).

### AOPP — report sections 8–10

Bob collects zero and one positions, independently shuffles both lists using system cryptographic randomness, and constructs `min(N0, N1)` disjoint zero–one pairs. Pair orientation and pair order are randomized before transmission: publishing zero-first pairs would reveal each paired bit's value.

Alice checks `a[i] XOR a[j]`. Even-parity pairs are rejected. For each odd-parity pair, Alice chooses one of its two positions uniformly at random and announces the selection. Both endpoints retain their own bit at that position, in shared pair order. Unpaired positions are discarded.

This rejects pairs with exactly one disagreement. Pairs with zero or two disagreements survive, so output equality is not guaranteed. AOPP randomness means repeated runs can produce different outputs.

The app implements the basic active-pair error-rejection operation with all available pairs. The equal-half virtual grouping and zigzag/concentration analysis in report section 12 are **not** implemented; no finite-key phase-error or key-rate claim is made.

### AD — report sections 13–17, equations 30–36

For block size `b >= 1`, complete, consecutive, non-overlapping blocks are processed in order; `N % b` trailing bits are discarded. Alice draws one fresh uniform mask bit `r` for each block and sends `m[i] = x[i] XOR r`. A large block uses the same mask throughout its chunks.

Bob computes `d[i] = y[i] XOR m[i]` and accepts only if all `d[i]` values are equal. He announces acceptance for the explicitly numbered block. Both endpoints retain the **first original bit** of each accepted block, as specified in equation 36. Neither `r` nor `d[0]` becomes the output bit. Blocks containing either zero errors or errors at every position survive. Block size 1 accepts all positions and gives no error rejection.

### AOPP+AD

AOPP runs once, then AD runs once on its corresponding output strings. Empty intermediate outputs are handled normally. There is no additional shuffle between stages.

## Communication and security boundary

`transport.py` requires TLS 1.3, dedicated-CA chain validation, validity checks, a signed CRL, and certificate role validation through OpenSSL. Alice verifies Bob's expected DNS identity; Bob explicitly authorizes Alice's expected DNS SAN. Both sides require a certificate. Session tickets are disabled. There is no plaintext fallback or verification bypass.

Each JSON record has a protocol version, fresh session identifier, sender role, directional sequence number, message type, round/block identifier, and expiration time. Length-prefixed framing handles partial TCP reads. Out-of-order messages, wrong sessions, mismatched settings, malformed indices, and expired messages abort the run.

The exchanged data are lengths/settings, randomly oriented pairing indices, acceptance/retention choices, masked AD blocks, and stage counts. Raw input strings and final output strings are not sent as protocol fields. The AD masking and parity disclosures are intentional public-protocol information; they are not substitutes for privacy amplification. No exact QBER is displayed because computing it from both entire private strings would require extra disclosure outside the requested operations.

As stated in report section 23, certificate-authenticated mTLS provides computational transport protection. This project does not implement information-theoretic transcript authentication, decoy estimation, finite-key bounds, error correction, key verification, or privacy amplification. Its outputs are processed bitstrings, not certified final QKD secret keys. No error-rejection method guarantees improvement for every arbitrary input.

## Code map

| File | Responsibility |
| --- | --- |
| `alice.py` | Independent Alice entry point and mTLS client |
| `bob.py` | Independent Bob entry point and mTLS listener |
| `ui.py` | Shared Streamlit input, connection, results, and download interface |
| `algorithms.py` | Input normalization, active pairing, parity and AD primitives |
| `protocol.py` | Coordinated AOPP/AD message flow and validation |
| `transport.py` | TLS setup, peer authorization, framing and record checks |
| `certificates.py` | Dedicated CA and separate endpoint certificate bundles |
| `tests/` | Algorithm, protocol, mTLS, and UI checks |

## Validation

```sh
python -m unittest discover -s tests -v
```

Tests cover the report's AOPP case table, exhaustive small AD blocks, empty/odd/single-value inputs, all three modes, retained-bit semantics, mismatched settings, multi-chunk AD, and certificate-authenticated endpoint communication. Tests use temporary certificate material and do not alter deployment certificates.

Validated locally with Python 3.12.10, Streamlit 1.64.0, and cryptography 46.0.7. The integration suite uses real TLS sockets on loopback and includes missing, untrusted, revoked, wrong-role, and wrong-identity certificate rejection. Streamlit AppTest checks both entry points, input errors, results, and empty outputs. Deployment across your actual servers still requires their network addresses, certificate bundles, and firewall configuration.

Implementation API references: [Python SSL documentation](https://docs.python.org/3/library/ssl.html) and [Streamlit file uploader documentation](https://docs.streamlit.io/develop/api-reference/widgets/st.file_uploader).
