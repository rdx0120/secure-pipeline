import struct

# Findings are reported at the DECODE line, not the use: the rule matches the
# statement sequence "decode a length ... use it unchecked", and semgrep anchors
# a sequence match at its first statement. Pointing at the decode is also the
# more useful triage target -- that is the field an attacker controls.


def read_chunk_unchecked(fh, buf):
    # ruleid: unbounded-binary-read
    length = struct.unpack("<I", fh.read(4))[0]
    return buf[:length]


def alloc_unchecked(fh):
    # ruleid: unbounded-binary-read
    size = struct.unpack("<Q", fh.read(8))[0]
    return bytearray(size)


def seek_unchecked(fh):
    # ruleid: unbounded-binary-read
    offset = int.from_bytes(fh.read(4), "little")
    fh.seek(offset)


def read_unchecked(fh):
    # ruleid: unbounded-binary-read
    n = struct.unpack("<I", fh.read(4))[0]
    return fh.read(n)


def slice_tail_unchecked(fh, buf):
    # ruleid: unbounded-binary-read
    offset = struct.unpack("<I", fh.read(4))[0]
    return buf[offset:]


# --- must NOT fire: validated against the remaining buffer ------------------

def read_chunk_checked(fh, buf):
    # ok: unbounded-binary-read
    length = struct.unpack("<I", fh.read(4))[0]
    if length > len(buf):
        raise ValueError("arena length field exceeds remaining bytes")
    return buf[:length]


def alloc_clamped(fh, remaining):
    # ok: unbounded-binary-read
    size = struct.unpack("<Q", fh.read(8))[0]
    return bytearray(min(size, remaining))


def seek_checked(fh, size):
    # ok: unbounded-binary-read
    offset = int.from_bytes(fh.read(4), "little")
    if offset >= size:
        raise ValueError("offset past end of arena")
    fh.seek(offset)
