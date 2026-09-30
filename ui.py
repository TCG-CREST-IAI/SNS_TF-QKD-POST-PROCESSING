"""Shared presentation; each endpoint accepts only its own private bitstring."""
import os
import streamlit as st
from algorithms import MODES, parse_bits


def render(role, process):
    name = role.title()
    st.set_page_config(page_title=f"{name} | AOPP + AD", page_icon="↔", layout="centered")
    st.markdown("""<style>
    .stApp { background: #f7f9fc; }
    .block-container { max-width: 900px; padding-top: 2.7rem; }
    h1 { letter-spacing: -.04em; }
    [data-testid="stMetric"] { background: white; padding: 1rem;
        border: 1px solid #e4e9f2; border-radius: 12px; }
    </style>""", unsafe_allow_html=True)
    st.caption("DISTRIBUTED BITSTRING PROCESSING · TLS 1.3")
    st.title(f"{name}'s workspace")
    st.write("Process corresponding bitstrings with AOPP, AD, or both in sequence.")
    st.caption("Each party enters its own bits on its own server. Start Bob first, then connect Alice.")
    with st.sidebar:
        st.subheader("mTLS connection")
        host = st.text_input("Bob host" if role == "alice" else "Listen address",
                             os.getenv("QKD_HOST", "127.0.0.1" if role == "alice" else "0.0.0.0"))
        port = st.number_input("Protocol port", 1, 65535, int(os.getenv("QKD_PORT", "8443")))
        peer = st.text_input("Expected peer DNS identity", os.getenv("QKD_PEER", "bob.local" if role == "alice" else "alice.local"))
        base = f"certs/{role}"
        ca = st.text_input("CA certificate path", os.getenv("QKD_CA", f"{base}/ca.pem"))
        crl = st.text_input("CA revocation list path", os.getenv("QKD_CRL", f"{base}/ca.crl.pem"))
        cert = st.text_input("Local certificate path", os.getenv("QKD_CERT", f"{base}/{role}.pem"))
        key = st.text_input("Local private key path", os.getenv("QKD_KEY", f"{base}/{role}.key"))
        timeout = st.number_input("Wait / socket timeout (seconds)", 10, 3600, 120)
        st.caption("Paths refer to this server. Only CA-authorized peers with the expected identity are accepted.")
    with st.form("run_form"):
        st.subheader("1 · Choose operation")
        mode = st.radio("Operation", MODES, horizontal=True, label_visibility="collapsed")
        block_size = st.number_input("AD block size", min_value=1, value=2, step=1,
                                     help="Used for AD and AOPP+AD. Incomplete final blocks are discarded.")
        st.subheader(f"2 · Enter {name}'s bits")
        source = st.radio("Input source", ["Text", "Text file"], horizontal=True)
        text = st.text_area("Bitstring", placeholder="01011010…", height=150)
        upload = st.file_uploader("UTF-8 text file", type=["txt"])
        st.caption("Spaces and line breaks are ignored. Both inputs must have the same length and position order.")
        submitted = st.form_submit_button("Connect and process" if role == "alice" else "Listen and process", type="primary", width="stretch")
    if submitted:
        st.session_state.pop("result", None)
        try:
            if source == "Text file":
                if upload is None:
                    raise ValueError("Select a text file first.")
                text = upload.getvalue().decode("utf-8-sig")
            bits = parse_bits(text)
            config = dict(host=host, port=int(port), peer=peer, ca=ca, crl=crl,
                          cert=cert, key=key, timeout=int(timeout))
            with st.spinner("Connecting to Bob…" if role == "alice" else "Waiting for Alice. Connect from Alice's workspace now…"):
                st.session_state.result = process(bits, mode, int(block_size), config)
        except (OSError, ValueError, ConnectionError, KeyError, TypeError) as error:
            st.error(f"Run stopped: {error}")
    if "result" in st.session_state:
        result = st.session_state.result
        st.subheader("Processed output")
        a, b, c = st.columns(3)
        a.metric("Input bits", result["input_bits"])
        b.metric("Output bits", result["output_bits"])
        c.metric("Retained", f"{100 * result['output_bits'] / result['input_bits']:.1f}%" if result["input_bits"] else "—")
        st.dataframe(result["stages"], hide_index=True, width="stretch")
        if result["bits"]:
            st.code(result["bits"][:4096] + ("…" if len(result["bits"]) > 4096 else ""), language=None)
        else:
            st.info("No bits survived this run.")
        st.download_button(f"Download {name}'s output", result["bits"], f"{role}_processed.txt", "text/plain")
        st.caption("Processed bits may still disagree. These are not final secret keys.")
