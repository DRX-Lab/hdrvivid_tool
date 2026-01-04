#!/usr/bin/env python3
# hdrvivid_tool.py
#
# Commands:
#   - info      (progress bar only)
#   - extract   (progress bar only) -> single BIN (u16len+payload per AU)
#   - remove    (progress bar only)
#   - inject    (prints like dovi_tool + EXACTLY TWO progress bars; no BIN bar)
#   - plot      (standalone; BIN -> PNG; no HEVC involved; progress bar only)
#
# HDR Vivid target (hardcoded):
#   SEI payloadType = 4 (user_data_registered_itu_t_t35)
#   country_code  = 0x26
#   provider_code = 0x0004
#
# Performance:
# - Uses fast start-code scanning via bytes.find (no per-byte loops for AnnexB)
# - Uses large read/write chunks (default 16 MiB)

import sys
import os
import argparse
from dataclasses import dataclass
from typing import List, Tuple, Optional

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

HDRVIVID_SEI_PT = 4
HDRVIVID_CC = 0x26
HDRVIVID_PC = 0x0004

DEFAULT_IO_CHUNK = 16 * 1024 * 1024  # 16 MiB

_START3 = b"\x00\x00\x01"


# ------------------------------------------------------------
# Progress bar
# ------------------------------------------------------------

def progress_bar(percent: float, width: int = 50):
    percent = max(0.0, min(100.0, percent))
    filled = int(width * percent / 100.0)
    bar = "■" * filled + " " * (width - filled)
    sys.stderr.write(f"\r[{bar}] {percent:5.1f}%")
    sys.stderr.flush()

def progress_done():
    progress_bar(100.0)
    sys.stderr.write("\n")
    sys.stderr.flush()

def print_status_line(msg: str):
    sys.stderr.write("\n" + msg + "\n")
    sys.stderr.flush()


# ------------------------------------------------------------
# CountingReader (reliable progress with buffered I/O)
# ------------------------------------------------------------

class CountingReader:
    """Wraps a binary file object and counts bytes read via .read()."""
    def __init__(self, f):
        self._f = f
        self.bytes_read = 0

    def read(self, n: int = -1) -> bytes:
        data = self._f.read(n)
        if data:
            self.bytes_read += len(data)
        return data

    def close(self):
        self._f.close()


# ------------------------------------------------------------
# Annex-B streaming NAL iterator (preserves start code length)
# ------------------------------------------------------------

def find_next_start_code(buf: bytearray, start: int) -> Optional[Tuple[int, int]]:
    pos = buf.find(_START3, start)
    if pos == -1:
        return None
    if pos > 0 and buf[pos - 1] == 0x00:
        return (pos - 1, 4)
    return (pos, 3)

def iter_annexb_nals_stream(f, chunk_size: int = DEFAULT_IO_CHUNK):
    """
    Streaming Annex-B NAL iterator.
    Yields: (start_code_len, nal_without_start_code)
    """
    buf = bytearray()
    eof = False
    offset = 0

    # Seek first start code
    while True:
        sc = find_next_start_code(buf, offset)
        if sc:
            pos, _ = sc
            if pos > 0:
                del buf[:pos]
            offset = 0
            break
        if eof:
            return
        chunk = f.read(chunk_size)
        if not chunk:
            eof = True
        else:
            buf.extend(chunk)

    while True:
        if len(buf) - offset < 4:
            if eof:
                return
            chunk = f.read(chunk_size)
            if not chunk:
                eof = True
            else:
                buf.extend(chunk)
            continue

        cur_sc_len = 4 if buf[offset:offset + 4] == b"\x00\x00\x00\x01" else 3

        next_sc = find_next_start_code(buf, offset + cur_sc_len)
        while next_sc is None and not eof:
            chunk = f.read(chunk_size)
            if not chunk:
                eof = True
                break
            buf.extend(chunk)
            next_sc = find_next_start_code(buf, offset + cur_sc_len)

        if next_sc is None and eof:
            nal = bytes(buf[offset + cur_sc_len:])
            yield (cur_sc_len, nal)
            return

        next_pos, _ = next_sc
        nal = bytes(buf[offset + cur_sc_len:next_pos])
        yield (cur_sc_len, nal)

        offset = next_pos
        if offset > 8 * 1024 * 1024:
            del buf[:offset]
            offset = 0


# ------------------------------------------------------------
# NAL helpers
# ------------------------------------------------------------

def nal_type_hevc(nal_wo_sc: bytes) -> int:
    if len(nal_wo_sc) < 1:
        return -1
    return (nal_wo_sc[0] >> 1) & 0x3F

def is_vcl(nal_type: int) -> bool:
    return 0 <= nal_type <= 31


# ------------------------------------------------------------
# RBSP / EPB
# ------------------------------------------------------------

def remove_emulation_prevention(ebsp: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    i = 0
    n = len(ebsp)
    while i < n:
        b = ebsp[i]
        if zeros == 2 and b == 3:
            i += 1
            zeros = 0
            continue
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
        if zeros > 2:
            zeros = 2
        i += 1
    return bytes(out)

def add_emulation_prevention(rbsp: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    for b in rbsp:
        if zeros >= 2 and b in (0, 1, 2, 3):
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)

def rbsp_trailing_bits() -> bytes:
    return b"\x80"


# ------------------------------------------------------------
# Minimal bitreader for AU fallback (slice header inspection)
# ------------------------------------------------------------

class _BitReader:
    __slots__ = ("_b", "_i", "_n")
    def __init__(self, data: bytes):
        self._b = data
        self._i = 0
        self._n = len(data) * 8

    def read_bits(self, k: int) -> int:
        if k <= 0:
            return 0
        if self._i + k > self._n:
            raise EOFError("bitreader overflow")
        v = 0
        for _ in range(k):
            byte = self._b[self._i >> 3]
            shift = 7 - (self._i & 7)
            v = (v << 1) | ((byte >> shift) & 1)
            self._i += 1
        return v

def hevc_first_slice_segment_in_pic_flag(nal_wo_sc: bytes) -> Optional[bool]:
    """
    Best-effort:
      For VCL NALs in HEVC, slice_segment_layer_rbsp begins with:
        first_slice_segment_in_pic_flag (1 bit)
    We remove EPB from nal[2:] (skipping 2-byte NAL header) and read the first bit.
    Returns True/False for decodable VCL NALs; None otherwise.
    """
    if len(nal_wo_sc) < 3:
        return None
    t = nal_type_hevc(nal_wo_sc)
    if not is_vcl(t):
        return None
    rbsp = remove_emulation_prevention(nal_wo_sc[2:])
    if not rbsp:
        return None
    try:
        br = _BitReader(rbsp)
        return bool(br.read_bits(1))
    except Exception:
        return None


# ------------------------------------------------------------
# SEI parsing/building (standards-correct FF-terminated pt/size)
# ------------------------------------------------------------

@dataclass
class SeiMessage:
    payload_type: int
    payload: bytes
    truncated: bool = False

def parse_sei_messages(rbsp: bytes) -> List[SeiMessage]:
    msgs: List[SeiMessage] = []
    i = 0
    n = len(rbsp)
    while i < n:
        # trailing bits
        if i == n - 1 and rbsp[i] == 0x80:
            break

        pt = 0
        while i < n and rbsp[i] == 0xFF:
            pt += 255
            i += 1
        if i >= n:
            break
        pt += rbsp[i]
        i += 1

        sz = 0
        while i < n and rbsp[i] == 0xFF:
            sz += 255
            i += 1
        if i >= n:
            break
        sz += rbsp[i]
        i += 1

        if i + sz > n:
            msgs.append(SeiMessage(pt, rbsp[i:], truncated=True))
            break

        payload = rbsp[i:i + sz]
        i += sz
        msgs.append(SeiMessage(pt, payload, truncated=False))

    return msgs

def _sei_write_ff_terminated(v: int, out: bytearray):
    x = int(v)
    while x >= 0xFF:
        out.append(0xFF)
        x -= 0xFF
    out.append(x & 0xFF)

def encode_sei_message(payload_type: int, payload: bytes) -> bytes:
    out = bytearray()
    _sei_write_ff_terminated(payload_type, out)
    _sei_write_ff_terminated(len(payload), out)
    out.extend(payload)
    return bytes(out)

def build_sei_prefix_nal(start_code_len: int, messages: List[SeiMessage]) -> bytes:
    start_code = b"\x00\x00\x01" if start_code_len == 3 else b"\x00\x00\x00\x01"
    nal_header = b"\x4E\x01"  # SEI_PREFIX
    rbsp = bytearray()
    for m in messages:
        rbsp.extend(encode_sei_message(m.payload_type, m.payload))
    rbsp.extend(rbsp_trailing_bits())
    ebsp = add_emulation_prevention(bytes(rbsp))
    return start_code + nal_header + ebsp


# ------------------------------------------------------------
# HDR Vivid detection
# ------------------------------------------------------------

def is_hdrvivid_t35(payload: bytes) -> bool:
    return (
        payload is not None and
        len(payload) >= 3 and
        payload[0] == HDRVIVID_CC and
        int.from_bytes(payload[1:3], "big") == HDRVIVID_PC
    )


# ------------------------------------------------------------
# BIN helpers
# ------------------------------------------------------------

def read_bin_all(path: str) -> List[Optional[bytes]]:
    with open(path, "rb") as f:
        data = f.read()

    out: List[Optional[bytes]] = []
    i = 0
    n = len(data)
    while i + 2 <= n:
        ln = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if ln == 0:
            out.append(None)
            continue
        if i + ln > n:
            break
        out.append(data[i:i + ln])
        i += ln
    return out

def normalize_bin_to_au_count_cycle(entries: List[Optional[bytes]], au_count: int) -> List[Optional[bytes]]:
    if au_count <= 0:
        return []
    if not entries:
        raise SystemExit("ERROR: Empty or invalid BIN file.")
    if len(entries) >= au_count:
        return entries[:au_count]
    out = list(entries)
    i = 0
    while len(out) < au_count:
        out.append(entries[i % len(entries)])
        i += 1
    return out


# ------------------------------------------------------------
# AU boundary tracking (AUD primary, slice-flag fallback)
# ------------------------------------------------------------

@dataclass
class AuTracker:
    """Tracks Access Unit index in a streaming Annex-B HEVC stream."""
    use_aud: bool
    au: int = -1
    saw_vcl: bool = False

    def feed(self, nal_wo_sc: bytes) -> Tuple[int, bool]:
        """
        Feed one NAL, return (current_au_index, boundary_started_now).
        - If boundary_started_now is True, a new AU began at this NAL.
        - If AU cannot be determined yet (no VCL and no AUD), returns au=-1.
        """
        t = nal_type_hevc(nal_wo_sc)

        # Primary mode: AUD
        if self.use_aud:
            if t == 35:  # AUD
                self.au += 1
                return self.au, True
            return self.au, False

        # Fallback mode: VCL first_slice flag
        if is_vcl(t):
            self.saw_vcl = True
            fs = hevc_first_slice_segment_in_pic_flag(nal_wo_sc)
            if self.au == -1:
                # First VCL anchors AU 0, even if fs is undecodable
                self.au = 0
                return self.au, True
            if fs is True:
                self.au += 1
                return self.au, True
            return self.au, False

        # Non-VCL NALs belong to current AU; if no AU yet, keep -1
        return self.au, False


def detect_aud_presence(path: str, chunk: int) -> bool:
    """Quick streaming scan to see if any AUD exists."""
    with open(path, "rb") as base:
        fin = CountingReader(base)
        for _, nal in iter_annexb_nals_stream(fin, chunk):
            if nal_type_hevc(nal) == 35:
                return True
    return False


# ------------------------------------------------------------
# INFO (streaming; progress by bytes read)
# ------------------------------------------------------------

def cmd_info(args):
    total = os.path.getsize(args.input)
    last = -1.0

    has_aud = detect_aud_presence(args.input, args.io_chunk)
    tracker = AuTracker(use_aud=has_aud)

    with open(args.input, "rb") as base:
        fin = CountingReader(base)

        for sc_len, nal in iter_annexb_nals_stream(fin, args.io_chunk):
            _au, _ = tracker.feed(nal)

            t = nal_type_hevc(nal)
            if t in (39, 40) and len(nal) >= 2:
                rbsp = remove_emulation_prevention(nal[2:])
                _ = parse_sei_messages(rbsp)

            pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
            if pct - last >= 0.1 or pct >= 100.0:
                progress_bar(pct)
                last = pct

    progress_done()

    # Validate we could determine AUs at least once for AU-dependent ops
    if not has_aud and not tracker.saw_vcl:
        raise SystemExit("ERROR: No AUD and no VCL NAL units detected; cannot infer Access Units.")


# ------------------------------------------------------------
# REMOVE (streaming; writes output while reading)
# ------------------------------------------------------------

def cmd_remove(args):
    total = os.path.getsize(args.input)
    last = -1.0

    has_aud = detect_aud_presence(args.input, args.io_chunk)
    tracker = AuTracker(use_aud=has_aud)

    with open(args.input, "rb") as base, open(args.output, "wb") as fout:
        fin = CountingReader(base)

        for sc_len, nal in iter_annexb_nals_stream(fin, args.io_chunk):
            tracker.feed(nal)

            t = nal_type_hevc(nal)
            start_code = b"\x00\x00\x01" if sc_len == 3 else b"\x00\x00\x00\x01"

            if t not in (39, 40) or len(nal) < 2:
                fout.write(start_code + nal)
            else:
                rbsp = remove_emulation_prevention(nal[2:])
                msgs = parse_sei_messages(rbsp)
                kept = [
                    SeiMessage(m.payload_type, m.payload, m.truncated)
                    for m in msgs
                    if not (m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload))
                ]
                if kept:
                    fout.write(build_sei_prefix_nal(sc_len, kept))
                # else drop SEI

            pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
            if pct - last >= 0.1 or pct >= 100.0:
                progress_bar(pct)
                last = pct

    progress_done()

    if not has_aud and not tracker.saw_vcl:
        raise SystemExit("ERROR: No AUD and no VCL NAL units detected; cannot infer Access Units.")


# ------------------------------------------------------------
# EXTRACT (streaming; writes BIN AU-by-AU as it goes)
# ------------------------------------------------------------

def cmd_extract(args):
    total = os.path.getsize(args.input)
    last = -1.0

    has_aud = detect_aud_presence(args.input, args.io_chunk)
    tracker = AuTracker(use_aud=has_aud)

    def write_bin_entry(bout, payload: Optional[bytes]):
        if payload is None:
            bout.write((0).to_bytes(2, "big"))
        else:
            ln = len(payload)
            if ln > 65535:
                raise SystemExit("ERROR: Payload too large for u16 BIN length.")
            bout.write(ln.to_bytes(2, "big"))
            bout.write(payload)

    with open(args.input, "rb") as base, open(args.output, "wb") as bout:
        fin = CountingReader(base)

        current_au = -1
        wrote_for_current = False
        stored_payload: Optional[bytes] = None
        ever_started_au = False

        for sc_len, nal in iter_annexb_nals_stream(fin, args.io_chunk):
            au, started = tracker.feed(nal)

            # On AU boundary: flush previous AU entry (if any)
            if started:
                ever_started_au = True
                if current_au >= 0:
                    write_bin_entry(bout, stored_payload if wrote_for_current else None)
                current_au = au
                wrote_for_current = False
                stored_payload = None

            t = nal_type_hevc(nal)
            if t in (39, 40) and len(nal) >= 2 and current_au >= 0:
                rbsp = remove_emulation_prevention(nal[2:])
                for m in parse_sei_messages(rbsp):
                    if m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload):
                        if not wrote_for_current:
                            stored_payload = m.payload
                            wrote_for_current = True
                        break

            pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
            if pct - last >= 0.1 or pct >= 100.0:
                progress_bar(pct)
                last = pct

        # Flush last AU
        if current_au >= 0:
            write_bin_entry(bout, stored_payload if wrote_for_current else None)

    progress_done()

    if not has_aud and not tracker.saw_vcl:
        raise SystemExit("ERROR: No AUD and no VCL NAL units detected; cannot infer Access Units.")
    if not has_aud and not ever_started_au:
        raise SystemExit("ERROR: Could not infer any AU boundary from slice headers.")


# ------------------------------------------------------------
# INJECT (two-pass streaming)
# ------------------------------------------------------------

def count_aus_streaming(path: str, chunk: int) -> int:
    """
    Counts AUs in a streaming pass:
      - If any AUD exists => count AUD NALs (each AUD starts an AU)
      - Else => infer AUs using VCL first_slice_segment_in_pic_flag
    """
    total = os.path.getsize(path)
    last = -1.0

    has_aud = detect_aud_presence(path, chunk)
    tracker = AuTracker(use_aud=has_aud)

    au_count = 0

    with open(path, "rb") as base:
        fin = CountingReader(base)
        for _, nal in iter_annexb_nals_stream(fin, chunk):
            au, started = tracker.feed(nal)
            if started and au >= 0:
                # AU indices start at 0; count by increments
                au_count = max(au_count, au + 1)

            pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
            if pct - last >= 0.1 or pct >= 100.0:
                progress_bar(pct)
                last = pct

    progress_done()

    if not has_aud and not tracker.saw_vcl:
        raise SystemExit("ERROR: No AUD and no VCL NAL units detected; cannot infer Access Units.")
    if au_count <= 0:
        raise SystemExit("ERROR: AU count is zero; cannot proceed.")
    return au_count


def cmd_inject(args):
    # NO bar for BIN parsing
    print("Parsing BIN file...")
    bin_entries = read_bin_all(args.bin)
    if not bin_entries:
        raise SystemExit("ERROR: Empty or invalid BIN file.")
    for p in bin_entries:
        if p is not None and not is_hdrvivid_t35(p):
            raise SystemExit("ERROR: BIN contains non-HDRVivid payload(s) (incorrect cc/pc).")

    # BAR #1: count AUs
    print("Processing input video for frame order info...")
    au_count = count_aus_streaming(args.input, args.io_chunk)
    if au_count <= 0:
        raise SystemExit("ERROR: Could not count Access Units.")

    if len(bin_entries) != au_count:
        sys.stderr.write(f"\nWarning: mismatched lengths. video {au_count}, BIN {len(bin_entries)}\n")
        if len(bin_entries) < au_count:
            sys.stderr.write("Metadata will be duplicated at the end to match video length\n")
        else:
            sys.stderr.write("Metadata will be skipped at the end to match video length\n")
        sys.stderr.flush()

    payloads_by_au = normalize_bin_to_au_count_cycle(bin_entries, au_count)

    # BAR #2: rewrite/inject STREAMING
    print("Rewriting file with interleaved HDR Vivid SEI NALs..")

    total = os.path.getsize(args.input)
    last = -1.0

    has_aud = detect_aud_presence(args.input, args.io_chunk)
    tracker = AuTracker(use_aud=has_aud)

    def au_payload(au: int) -> Optional[bytes]:
        if au < 0 or au >= len(payloads_by_au):
            return None
        p = payloads_by_au[au]
        if p is None or len(p) == 0:
            return None
        return p

    with open(args.input, "rb") as base, open(args.output, "wb") as fout:
        fin = CountingReader(base)

        current_au = -1
        inserted = False       # ensured an HDRVivid for this AU
        inserted_by_us = False # we inserted a new SEI before first VCL

        for sc_len, nal in iter_annexb_nals_stream(fin, args.io_chunk):
            au, started = tracker.feed(nal)
            t = nal_type_hevc(nal)
            start_code = b"\x00\x00\x01" if sc_len == 3 else b"\x00\x00\x00\x01"

            # On AU boundary, reset per-AU state
            if started:
                current_au = au
                inserted = False
                inserted_by_us = False

            pld = au_payload(current_au)

            # Insert before first VCL in AU if needed
            if is_vcl(t) and (not inserted) and (pld is not None) and current_au >= 0:
                fout.write(build_sei_prefix_nal(sc_len, [SeiMessage(HDRVIVID_SEI_PT, pld, False)]))
                inserted = True
                inserted_by_us = True

            # Handle SEI (replace/remove duplicates)
            if t in (39, 40) and len(nal) >= 2:
                rbsp = remove_emulation_prevention(nal[2:])
                msgs = parse_sei_messages(rbsp)

                has_hdr = any(
                    (m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload))
                    for m in msgs
                )

                if not has_hdr:
                    fout.write(start_code + nal)
                else:
                    if pld is None:
                        # BIN says "no insert": preserve original
                        fout.write(start_code + nal)
                    else:
                        if inserted_by_us:
                            # we already inserted earlier, remove HDRVivid here to avoid duplicates
                            kept = [
                                SeiMessage(m.payload_type, m.payload, m.truncated)
                                for m in msgs
                                if not (m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload))
                            ]
                            if kept:
                                fout.write(build_sei_prefix_nal(sc_len, kept))
                            # else drop
                        else:
                            # replace first HDRVivid message
                            new_msgs: List[SeiMessage] = []
                            replaced = False
                            for m in msgs:
                                if (not replaced) and m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload):
                                    new_msgs.append(SeiMessage(HDRVIVID_SEI_PT, pld, False))
                                    replaced = True
                                else:
                                    new_msgs.append(SeiMessage(m.payload_type, m.payload, m.truncated))
                            fout.write(build_sei_prefix_nal(sc_len, new_msgs))
                            inserted = True
                            inserted_by_us = False

                pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
                if pct - last >= 0.1 or pct >= 100.0:
                    progress_bar(pct)
                    last = pct
                continue

            # Default: pass-through
            fout.write(start_code + nal)

            pct = (fin.bytes_read * 100.0 / total) if total > 0 else 100.0
            if pct - last >= 0.1 or pct >= 100.0:
                progress_bar(pct)
                last = pct

    progress_done()

    if not has_aud and not tracker.saw_vcl:
        raise SystemExit("ERROR: No AUD and no VCL NAL units detected; cannot infer Access Units.")


# ------------------------------------------------------------
# PLOT (BIN-only) — unchanged from your prior version
# ------------------------------------------------------------
import math

_PQ_M1 = 2610.0 / 16384.0
_PQ_M2 = 2523.0 / 32.0
_PQ_C1 = 3424.0 / 4096.0
_PQ_C2 = 2413.0 / 128.0
_PQ_C3 = 2392.0 / 128.0

def nits_to_pq(nits: float) -> float:
    """Absolute luminance (nits) -> PQ code value [0..1]."""
    n = max(0.0, float(nits)) / 10000.0
    if n <= 0.0:
        return 0.0
    n_m1 = n ** _PQ_M1
    num = _PQ_C1 + _PQ_C2 * n_m1
    den = 1.0 + _PQ_C3 * n_m1
    return (num / den) ** _PQ_M2

def pq_to_nits(pq: float) -> float:
    """PQ code value [0..1] -> absolute luminance (nits)."""
    v = max(0.0, min(1.0, float(pq)))
    if v <= 0.0:
        return 0.0
    v_1_m2 = v ** (1.0 / _PQ_M2)
    num = max(0.0, v_1_m2 - _PQ_C1)
    den = _PQ_C2 - _PQ_C3 * v_1_m2
    if den <= 0.0:
        return 10000.0
    n = (num / den) ** (1.0 / _PQ_M1)
    return n * 10000.0

def _extract_hdrvivid_fields_from_t35(payload: bytes):
    """
    Extract HDR Vivid CUVA fields from a T.35 payload entry (as stored in your BIN).
    Expected CUVA wrapper:
      [0]   country_code = 0x26
      [1:3] provider_code = 0x0004
      [3:5] provider_oriented_code = 0x0005
      [5]   system_start_code = 0x01
    Then bitstream: min12, avg12, var12, max12 (12 bits each), tm_flag (1), sat_flag (1)
    """
    if not payload or len(payload) < 6:
        return None
    cc = payload[0]
    pc = int.from_bytes(payload[1:3], "big")
    poc = int.from_bytes(payload[3:5], "big")
    if cc != HDRVIVID_CC or pc != HDRVIVID_PC:
        return None
    if poc != 0x0005:
        return None
    ssc = payload[5]
    if ssc != 0x01:
        return None
    data = payload[6:]
    if not data:
        return None

    class _BR:
        __slots__ = ("b", "i", "n")
        def __init__(self, b: bytes):
            self.b = b
            self.i = 0
            self.n = len(b) * 8
        def read(self, k: int) -> int:
            if k < 0 or self.i + k > self.n:
                raise EOFError
            v = 0
            for _ in range(k):
                byte = self.b[self.i >> 3]
                shift = 7 - (self.i & 7)
                v = (v << 1) | ((byte >> shift) & 1)
                self.i += 1
            return v
        def tell_bytes(self) -> int:
            return self.i // 8

    try:
        br = _BR(data)
        min12 = br.read(12)
        avg12 = br.read(12)
        var12 = br.read(12)
        max12 = br.read(12)
        tm_flag = br.read(1)
        sat_flag = br.read(1)
        tail_off = br.tell_bytes()
        tail = data[tail_off:]
    except Exception:
        return None

    return {"min12": min12, "avg12": avg12, "var12": var12, "max12": max12,
            "tm_flag": tm_flag, "sat_flag": sat_flag, "tail": tail}

def plot_hdrvivid_style_png(path_png: str, entries, bin_name: str):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        raise SystemExit(f"ERROR: matplotlib import failed: {type(e).__name__}: {e}") from e

    n = len(entries)
    if n <= 0:
        raise SystemExit("ERROR: BIN is empty; cannot plot.")

    MAXSCL_COLOR = (65 / 255.0, 105 / 255.0, 225 / 255.0)
    AVERAGE_COLOR = (75 / 255.0, 0 / 255.0, 130 / 255.0)
    MINIMUM_COLOR = (0.10, 0.10, 0.10)

    def u12_to_nits(u: int) -> float:
        u = max(0, min(4095, int(u)))
        return (u / 4095.0) * 1000.0

    max_pq, avg_pq, min_pq = [], [], []
    missing = 0
    invalid = 0
    floor_pq = nits_to_pq(0.01)

    for p in entries:
        if p is None:
            missing += 1
            max_pq.append(floor_pq); avg_pq.append(floor_pq); min_pq.append(floor_pq)
            continue
        dec = _extract_hdrvivid_fields_from_t35(p)
        if not dec:
            invalid += 1
            max_pq.append(floor_pq); avg_pq.append(floor_pq); min_pq.append(floor_pq)
            continue
        max_pq.append(nits_to_pq(u12_to_nits(dec["max12"])))
        avg_pq.append(nits_to_pq(u12_to_nits(dec["avg12"])))
        min_pq.append(nits_to_pq(u12_to_nits(dec["min12"])))

    valid_max_nits = [pq_to_nits(v) for v in max_pq if v > nits_to_pq(0.02)]
    valid_avg_nits = [pq_to_nits(v) for v in avg_pq if v > nits_to_pq(0.02)]
    valid_min_nits = [pq_to_nits(v) for v in min_pq if v > nits_to_pq(0.02)]

    maxcll = max(valid_max_nits) if valid_max_nits else 0.01
    maxcll_avg = (sum(valid_max_nits) / len(valid_max_nits)) if valid_max_nits else 0.01
    maxfall = max(valid_avg_nits) if valid_avg_nits else 0.01
    maxfall_avg = (sum(valid_avg_nits) / len(valid_avg_nits)) if valid_avg_nits else 0.01
    minval = min(valid_min_nits) if valid_min_nits else 0.01

    thresholds = [100, 150, 200, 400, 600, 1000, 2000, 4000]
    def pct_above(series, thr):
        if not series: return 0.0
        c = sum(1 for x in series if x > thr)
        return (c / len(series)) * 100.0

    lines = []
    lines.append(f"MaxFALL: {maxfall:.2f} nits (avg: {maxfall_avg:.2f})")
    for t in thresholds:
        lines.append(f"MaxFALL Percentage Above {t}nits: {pct_above(valid_avg_nits, t):.2f}")
    lines.append("")
    lines.append(f"MaxCLL: {maxcll:.2f} nits (avg: {maxcll_avg:.2f})")
    for t in thresholds:
        lines.append(f"MaxCLL Percentage Above {t}nits: {pct_above(valid_max_nits, t):.2f}")
    stats_block = "\n".join(lines)

    x = list(range(n))
    fig = plt.figure(figsize=(30.0, 12.0), dpi=100)
    ax = fig.add_subplot(111)
    ax.set_title("HDR Vivid (CUVA) Luminance Plot", fontsize=22, pad=24)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("frames", fontsize=14)
    ax.set_ylabel("nits (cd/m²)", fontsize=14)
    ax.grid(True, which="major", alpha=0.10, linewidth=1.2)
    ax.grid(True, which="minor", alpha=0.03, linewidth=0.8)
    ax.minorticks_on()

    key_nits = [0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0,
                200.0, 400.0, 600.0, 1000.0, 2000.0, 4000.0, 10000.0]
    key_pq = [nits_to_pq(v) for v in key_nits]
    ax.set_yticks(key_pq)
    ax.set_yticklabels([("{:.3f}".format(v)).rstrip("0").rstrip(".") for v in key_nits], fontsize=11)

    max_label = f"Maximum (MaxCLL: {maxcll:.2f} nits, avg: {maxcll_avg:.2f} nits)"
    avg_label = f"Average (MaxFALL: {maxfall:.2f} nits, avg: {maxfall_avg:.2f} nits)"
    min_label = f"Minimum (min: {minval:.3f} nits)" if minval < 1.0 else f"Minimum (min: {minval:.2f} nits)"

    ax.fill_between(x, max_pq, 0.0, alpha=0.25, linewidth=0.0, color=MAXSCL_COLOR)
    ax.plot(x, max_pq, linewidth=1.5, color=MAXSCL_COLOR, label=max_label)

    ax.fill_between(x, avg_pq, 0.0, alpha=0.50, linewidth=0.0, color=AVERAGE_COLOR)
    ax.plot(x, avg_pq, linewidth=1.5, color=AVERAGE_COLOR, label=avg_label)

    ax.plot(x, min_pq, linewidth=1.0, color=MINIMUM_COLOR, alpha=0.75, label=min_label)

    leg = ax.legend(loc="lower left", framealpha=1.0, fontsize=12)
    leg.get_frame().set_linewidth(1.0)

    caption1 = f"{bin_name}"
    caption2 = f"Entries: {n}. Missing entries: {missing}. Invalid payloads: {invalid}."
    caption3 = "Scale: 4095 -> 1000 nits. Source: CUVA max12/avg12 fields."
    fig.text(0.06, 0.94, caption1, fontsize=12, ha="left", va="top")
    fig.text(0.06, 0.92, caption2, fontsize=12, ha="left", va="top")
    fig.text(0.06, 0.90, caption3, fontsize=12, ha="left", va="top")
    fig.text(0.99, 0.94, stats_block, fontsize=10, ha="right", va="top")
    fig.subplots_adjust(left=0.06, right=0.99, top=0.88, bottom=0.10)
    fig.savefig(path_png)
    plt.close(fig)

def cmd_plot(args):
    entries = read_bin_all(args.input)
    total = len(entries) if entries else 1
    last = -1.0
    for i in range(total):
        pct = (i + 1) * 50.0 / total
        if pct - last >= 0.1 or pct >= 50.0:
            progress_bar(pct)
            last = pct
    plot_hdrvivid_style_png(args.output, entries, os.path.basename(args.input))
    progress_bar(100.0)
    progress_done()


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="hdrvivid_tool",
        description="HDR Vivid tool for HEVC Annex-B: info/extract/remove/inject + standalone plot (BIN->PNG)."
    )
    p.add_argument("--io-chunk", type=int, default=DEFAULT_IO_CHUNK,
                   help=f"Read/write chunk size in bytes (default {DEFAULT_IO_CHUNK})")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("info", help="Parse/validate stream (progress bar only)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("extract", help="Extract HDR Vivid to BIN (streaming write)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("-o", "--output", required=True, help="Output .bin")
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser("remove", help="Remove HDR Vivid metadata (streaming write)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("-o", "--output", required=True, help="Output .hevc")
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("inject", help="Inject/replace HDR Vivid from BIN (two bars, streaming rewrite)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("--bin", required=True, help="Input .bin produced by extract")
    sp.add_argument("-o", "--output", required=True, help="Output .hevc")
    sp.set_defaults(func=cmd_inject)

    sp = sub.add_parser("plot", help="Standalone plot: BIN -> PNG (no HEVC)")
    sp.add_argument("-i", "--input", required=True, help="Input .bin")
    sp.add_argument("-o", "--output", required=True, help="Output .png")
    sp.set_defaults(func=cmd_plot)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
