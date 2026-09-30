"""One coordinated run over a persistent authenticated connection."""
import secrets
from algorithms import MODES, active_pairs, odd_parity, accept_block

BATCH = 512
CHUNK = 32768


def require(condition, message="Invalid peer protocol data."):
    if not condition:
        raise ValueError(message)


def run(channel, bits, mode, block_size):
    require(mode in MODES and type(block_size) is int and block_size >= 1)
    alice = channel.role == "alice"
    settings = dict(length=len(bits), mode=mode, block_size=block_size)
    if alice:
        channel.send("settings", settings)
        require(channel.receive("settings") == settings, "Inputs or operation settings differ between endpoints.")
    else:
        peer = channel.receive("settings")
        channel.send("settings", settings)
        require(peer == settings, "Inputs or operation settings differ between endpoints.")
    stats = []
    original = len(bits)
    if "AOPP" in mode:
        before = len(bits)
        pairs = None if alice else active_pairs(bits)
        if alice:
            count = channel.receive("pair_count")
            require(type(count) is int and 0 <= count <= len(bits) // 2)
        else:
            count = len(pairs)
            channel.send("pair_count", count)
        output = []
        seen = set()
        for start in range(0, count, BATCH):
            if alice:
                batch = channel.receive("pairs", start)
                require(isinstance(batch, list) and len(batch) == min(BATCH, count-start))
                choices = []
                for pair in batch:
                    require(isinstance(pair, list) and len(pair) == 2)
                    for index in pair:
                        require(type(index) is int and 0 <= index < before and index not in seen)
                        seen.add(index)
                    choice = secrets.randbits(1) if odd_parity(bits, pair) else -1
                    choices.append(choice)
                    if choice != -1:
                        output.append(bits[pair[choice]])
                channel.send("choices", choices, start)
            else:
                batch = pairs[start:start+BATCH]
                channel.send("pairs", batch, start)
                choices = channel.receive("choices", start)
                require(isinstance(choices, list) and len(choices) == len(batch))
                for pair, choice in zip(batch, choices):
                    require(type(choice) is int and choice in (-1, 0, 1))
                    if choice != -1:
                        output.append(bits[pair[choice]])
        bits = "".join(output)
        stats.append(dict(stage="AOPP", input_bits=before, groups=count,
                          accepted=len(bits), discarded_unpaired=before-2*count,
                          output_bits=len(bits)))
    if "AD" in mode:
        before = len(bits)
        count = before // block_size
        output = []
        for block_id in range(count):
            start = block_id * block_size
            # One fresh mask per block, including across chunk boundaries.
            mask = secrets.randbits(1) if alice else None
            first_difference = None
            accepted = True
            for offset in range(0, block_size, CHUNK):
                block = bits[start+offset:start+min(offset+CHUNK, block_size)]
                if alice:
                    message = "".join(str(int(bit) ^ mask) for bit in block)
                    channel.send("masked", dict(offset=offset, bits=message), block_id)
                else:
                    message = channel.receive("masked", block_id)
                    require(isinstance(message, dict) and message.get("offset") == offset)
                    masked = message.get("bits")
                    require(isinstance(masked, str) and len(masked) == len(block)
                            and all(bit in "01" for bit in masked))
                    difference = block[0] != masked[0]
                    if first_difference is None:
                        first_difference = difference
                    accepted &= accept_block(block, masked) and difference == first_difference
            if alice:
                accepted = channel.receive("accepted", block_id)
                require(type(accepted) is bool)
            else:
                channel.send("accepted", accepted, block_id)
            if accepted:
                output.append(bits[start])
        bits = "".join(output)
        stats.append(dict(stage="AD", input_bits=before, groups=count,
                          accepted=len(bits), discarded_tail=before % block_size,
                          output_bits=len(bits)))
    summary = dict(input_bits=original, output_bits=len(bits), stages=stats)
    if alice:
        channel.send("complete", summary)
        require(channel.receive("complete") == summary, "Final counts disagree; discard the run.")
    else:
        require(channel.receive("complete") == summary, "Final counts disagree; discard the run.")
        channel.send("complete", summary)
    return dict(bits=bits, **summary)
