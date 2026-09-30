"""Bob's independent Streamlit application and one-run mTLS listener."""
import socket
import time
from protocol import run
from transport import Channel, authorize, tls_context


def process(bits, mode, block_size, config, ready=None):
    context = tls_context("bob", config["ca"], config["cert"], config["key"], config["crl"])
    deadline = time.monotonic() + config["timeout"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((config["host"], config["port"]))
        listener.listen(5)
        if ready:
            ready(listener.getsockname()[1])
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("No authorized Alice connected before the wait expired.")
            listener.settimeout(remaining)
            raw, _ = listener.accept()
            raw.settimeout(min(10, remaining))
            secure = None
            try:
                secure = context.wrap_socket(raw, server_side=True)
                authorize(secure, config["peer"])
            except (OSError, ValueError):
                raw.close()
                if secure is not None:
                    secure.close()
                continue
            with secure:
                secure.settimeout(config["timeout"])
                return run(Channel(secure, "bob", None), bits, mode, block_size)


if __name__ == "__main__":
    from ui import render
    render("bob", process)
