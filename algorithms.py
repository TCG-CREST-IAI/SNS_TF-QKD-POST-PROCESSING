"""Local AOPP and AD primitives; no raw peer keys are required."""
import secrets

MODES = ("AOPP", "AD", "AOPP+AD")


def parse_bits(text):
    bits = "".join(text.lstrip("\ufeff").split())
    if any(bit not in "01" for bit in bits):
        raise ValueError("Use only 0, 1 and whitespace.")
    return bits


def active_pairs(bits):
    zeros = [i for i, bit in enumerate(bits) if bit == "0"]
    ones = [i for i, bit in enumerate(bits) if bit == "1"]
    rng = secrets.SystemRandom()
    rng.shuffle(zeros)
    rng.shuffle(ones)
    # Random orientation prevents the announced position order revealing values.
    pairs = [(a, b) if secrets.randbits(1) else (b, a)
             for a, b in zip(zeros, ones)]
    rng.shuffle(pairs)
    return pairs


def odd_parity(bits, pair):
    return bits[pair[0]] != bits[pair[1]]


def masked_block(block):
    mask = secrets.randbits(1)
    return "".join(str(int(bit) ^ mask) for bit in block)


def accept_block(block, masked):
    if len(block) != len(masked) or not block:
        raise ValueError("AD blocks must be nonempty and equally sized.")
    first = block[0] != masked[0]
    return all((a != b) == first for a, b in zip(block, masked))
