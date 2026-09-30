"""Alice's independent Streamlit application and mTLS client."""
import secrets
from protocol import run
from transport import Channel, connect, tls_context


def process(bits, mode, block_size, config):
    context = tls_context("alice", config["ca"], config["cert"], config["key"], config["crl"])
    with connect(context, config["host"], config["port"], config["peer"], config["timeout"]) as sock:
        return run(Channel(sock, "alice", secrets.token_hex(32)), bits, mode, block_size)


if __name__ == "__main__":
    from ui import render
    render("alice", process)
