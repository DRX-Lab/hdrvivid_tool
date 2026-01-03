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
import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
from collections import defaultdict

HDRVIVID_SEI_PT = 4
HDRVIVID_CC = 0x26
HDRVIVID_PC = 0x0004

DEFAULT_IO_CHUNK = 16 * 1024 * 1024  # 16 MiB


# ----------------------------
# Progress bar
# ----------------------------
def progress_bar(percent: float, width: int = 50):
    if percent < 0:
        percent = 0.0
    if percent > 100.0:
        percent = 100.0
    filled = int(width * percent / 100.0)
    bar = "■" * filled + " " * (width - filled)
    sys.stderr.write(f"\r[{bar}] {percent:5.1f}%")
    sys.stderr.flush()

def progress_done():
    progress_bar(100.0)
    sys.stderr.write("\n")
    sys.stderr.flush()

def print_status_line(msg: str):
    # Always start on a clean line, preventing collisions with the bar
    sys.stderr.write("\n" + msg + "\n")
    sys.stderr.flush()


# ----------------------------
# Fast I/O with scaled progress
# ----------------------------
def read_file_with_progress_scaled(path: str, chunk_size: int, lo: float, hi: float) -> bytes:
    with open(path, "rb") as f:
        try:
            f.seek(0, 2)
            total = f.tell()
            f.seek(0)
        except Exception:
            total = 0

        if total <= 0:
            data = f.read()
            progress_bar(hi)
            return data

        buf = bytearray()
        read_bytes = 0
        last = -1.0

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf.extend(chunk)
            read_bytes += len(chunk)
            pct = lo + (read_bytes * (hi - lo) / total)
            if pct - last >= 0.1 or pct >= hi:
                progress_bar(pct)
                last = pct

        progress_bar(hi)
        return bytes(buf)

def write_bytes_with_progress(path: str, data: bytes, lo: float, hi: float, chunk_size: int = DEFAULT_IO_CHUNK):
    total = len(data)
    if total <= 0:
        with open(path, "wb") as f:
            f.write(data)
        progress_bar(hi)
        return

    with open(path, "wb") as f:
        written = 0
        last = -1.0
        mv = memoryview(data)
        while written < total:
            n = min(chunk_size, total - written)
            f.write(mv[written:written + n])
            written += n
            pct = lo + (written * (hi - lo) / total)
            if pct - last >= 0.1 or pct >= hi:
                progress_bar(pct)
                last = pct
        progress_bar(hi)


# ----------------------------
# Fast Annex-B start-code scanning using .find
# ----------------------------
def find_start_codes_fast(data: bytes) -> List[int]:
    b = data
    n = len(b)
    out: List[int] = []
    pat = b"\x00\x00\x01"

    i = 0
    last_added = -1
    while True:
        j = b.find(pat, i)
        if j == -1:
            break

        sc_pos = j
        if j > 0 and b[j - 1] == 0x00:
            sc_pos = j - 1

        if sc_pos != last_added and sc_pos + 3 < n:
            out.append(sc_pos)
            last_added = sc_pos

        i = j + 3

    return out

def get_nal_unit(data: bytes, start: int, end: int) -> Tuple[bytes, int]:
    chunk = data[start:end]
    if chunk.startswith(b"\x00\x00\x01"):
        return chunk[3:], 3
    if chunk.startswith(b"\x00\x00\x00\x01"):
        return chunk[4:], 4
    return b"", 0

def nal_type_hevc(nal: bytes) -> int:
    if len(nal) < 1:
        return -1
    return (nal[0] >> 1) & 0x3F


# ----------------------------
# RBSP / EPB
# ----------------------------
def remove_emulation_prevention(ebsp: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    i = 0
    while i < len(ebsp):
        b = ebsp[i]
        if zeros == 2 and b == 3:
            i += 1
            zeros = 0
            continue
        out.append(b)
        if b == 0:
            zeros = min(2, zeros + 1)
        else:
            zeros = 0
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


# ----------------------------
# SEI parsing/building
# ----------------------------
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
            payload = rbsp[i:]
            msgs.append(SeiMessage(pt, payload, truncated=True))
            break

        payload = rbsp[i:i + sz]
        i += sz
        msgs.append(SeiMessage(pt, payload, truncated=False))

    return msgs

def encode_sei_message(payload_type: int, payload: bytes) -> bytes:
    out = bytearray()

    pt = payload_type
    while pt >= 0xFF:
        out.append(0xFF)
        pt -= 0xFF
    out.append(pt)

    sz = len(payload)
    while sz >= 0xFF:
        out.append(0xFF)
        sz -= 0xFF
    out.append(sz)

    out.extend(payload)
    return bytes(out)

def build_sei_prefix_nal(messages: List[SeiMessage]) -> bytes:
    nal_header = b"\x4E\x01"  # SEI_PREFIX
    rbsp = bytearray()
    for m in messages:
        rbsp.extend(encode_sei_message(m.payload_type, m.payload))
    rbsp.extend(rbsp_trailing_bits())
    ebsp = add_emulation_prevention(bytes(rbsp))
    return b"\x00\x00\x01" + nal_header + ebsp


# ----------------------------
# HDR Vivid detection (hardcoded)
# ----------------------------
def is_hdrvivid_t35(payload: bytes) -> bool:
    if len(payload) < 3:
        return False
    cc = payload[0]
    pc = int.from_bytes(payload[1:3], "big")
    return (cc == HDRVIVID_CC) and (pc == HDRVIVID_PC)


# ----------------------------
# Minimal bitreader (for slice header inspection)
# ----------------------------
class _BitReader:
    __slots__ = ("_b", "_i", "_n")
    def __init__(self, data: bytes):
        self._b = data
        self._i = 0  # bit index
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

def _hevc_first_slice_segment_in_pic_flag(nal: bytes) -> Optional[bool]:
    """Best-effort: returns True/False for VCL NALs, otherwise None.

    For HEVC slice_segment_layer_rbsp, the first bit is first_slice_segment_in_pic_flag.
    We only need this 1-bit flag to approximate Access Unit boundaries when AUD is absent.
    """
    if len(nal) < 3:
        return None
    t = nal_type_hevc(nal)
    if not (0 <= t <= 31):
        return None
    rbsp = remove_emulation_prevention(nal[2:])
    if not rbsp:
        return None
    try:
        br = _BitReader(rbsp)
        return bool(br.read_bits(1))
    except Exception:
        return None

# ----------------------------
# NAL model and AU mapping
# ----------------------------
@dataclass
class NalUnit:
    start: int
    end: int
    nal_type: int
    nal: bytes

def parse_nals_fast(data: bytes) -> List[NalUnit]:
    sc = find_start_codes_fast(data)
    sc.append(len(data))
    nals: List[NalUnit] = []
    for i in range(len(sc) - 1):
        s, e = sc[i], sc[i + 1]
        nal, _ = get_nal_unit(data, s, e)
        if not nal:
            continue
        nals.append(NalUnit(s, e, nal_type_hevc(nal), nal))
    return nals

def compute_au_map(nals: List[NalUnit]) -> List[int]:
    """Map each NAL to an Access Unit index.

    Primary method: use AUD (nal_type 35).
    Fallback (when AUD is absent): start a new AU on each VCL NAL whose
    first_slice_segment_in_pic_flag == 1 (or on the first VCL seen).
    """
    # Primary: AUD (NAL 35)
    if any(n.nal_type == 35 for n in nals):
        au = -1
        out: List[int] = []
        for n in nals:
            if n.nal_type == 35:
                au += 1
            out.append(au)
        return out

    # Fallback: derive AU boundaries from slice headers (best-effort)
    au = -1
    out: List[int] = []
    saw_vcl = False

    for n in nals:
        t = n.nal_type
        if 0 <= t <= 31:  # VCL
            saw_vcl = True
            fs = _hevc_first_slice_segment_in_pic_flag(n.nal)
            if au == -1 or fs is True:
                au += 1
            out.append(au)
        else:
            # Parameter sets / SEI, etc. belong to the current AU; if we haven't
            # reached the first VCL yet, treat them as AU 0 for practical use.
            out.append(au if au >= 0 else 0)

    if not saw_vcl:
        return [-1] * len(nals)
    return out

def first_vcl_in_au(nals: List[NalUnit], au_map: List[int], au: int) -> Optional[int]:
    for i, n in enumerate(nals):
        if au_map[i] == au and 0 <= n.nal_type <= 31:
            return i
    return None


# ----------------------------
# BIN format: u16_be length + payload per entry
# ----------------------------
def write_bin(path: str, payloads_by_au: List[Optional[bytes]], lo: float, hi: float):
    total = len(payloads_by_au) if payloads_by_au else 1
    with open(path, "wb") as f:
        last = -1.0
        for i, p in enumerate(payloads_by_au):
            if p is None:
                f.write((0).to_bytes(2, "big"))
            else:
                ln = len(p)
                if ln > 65535:
                    raise ValueError("Payload too large for u16 length.")
                f.write(ln.to_bytes(2, "big"))
                f.write(p)

            pct = lo + (i + 1) * (hi - lo) / total
            if pct - last >= 0.1 or pct >= hi:
                progress_bar(pct)
                last = pct
        progress_bar(hi)

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

def normalize_bin_to_au_count_cycle(bin_entries: List[Optional[bytes]], au_count: int) -> List[Optional[bytes]]:
    if au_count <= 0:
        return []
    if not bin_entries:
        raise SystemExit("ERROR: Empty or invalid BIN file.")
    if len(bin_entries) >= au_count:
        return bin_entries[:au_count]
    out = list(bin_entries)
    i = 0
    while len(out) < au_count:
        out.append(bin_entries[i % len(bin_entries)])
        i += 1
    return out

# ----------------------------
# Standalone plot (BIN -> PNG) - UPDATED (decodes CUVA HDR Vivid fields)
# Rust/plotters-like design: PQ axis (0..1) with nits tick labels, two filled areas, big canvas.
# ----------------------------

import math

# ST 2084 (PQ) constants
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

    Expected layout (from your samples):
      [0]        country_code = 0x26
      [1:3]      provider_code = 0x0004
      [3:5]      provider_oriented_code = 0x0005
      [5]        system_start_code = 0x01
      then bitstream:
        min12, avg12, var12, max12 (each 12 bits)
        tm_flag (1 bit)
        sat_flag (1 bit)
        remaining bits/bytes (tail), often ends with 0x00

    Returns dict with decoded values or None if invalid.
    """
    if not payload or len(payload) < 6:
        return None

    # Validate CUVA wrapper
    cc = payload[0]
    pc = int.from_bytes(payload[1:3], "big")
    poc = int.from_bytes(payload[3:5], "big")

    if cc != HDRVIVID_CC or pc != HDRVIVID_PC:
        return None
    if poc != 0x0005:
        return None

    # Validate system_start_code
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

    return {
        "min12": min12,
        "avg12": avg12,
        "var12": var12,
        "max12": max12,
        "tm_flag": tm_flag,
        "sat_flag": sat_flag,
        "tail": tail,
        "country_code": cc,
        "provider_code": pc,
        "provider_oriented_code": poc,
        "system_start_code": ssc,
    }


def plot_hdrvivid_style_png(path_png: str, entries, bin_name: str):
    """
    Rust/plotters-like design:
      - PQ Y-axis (0..1) with key-point ticks labeled in nits
      - Two filled area series: Maximum + Average
      - Big canvas (3000x1200), margins, mesh, legend lower-left
      - Captions at top-left (file, entries, missing/invalid, scale)
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        raise SystemExit(f"ERROR: matplotlib import failed: {type(e).__name__}: {e}") from e

    n = len(entries)
    if n <= 0:
        raise SystemExit("ERROR: BIN is empty; cannot plot.")

    # Match Rust example colors
    MAXSCL_COLOR = (65/255.0, 105/255.0, 225/255.0)  # royalblue
    AVERAGE_COLOR = (75/255.0, 0/255.0, 130/255.0)   # indigo

    # Scale 12-bit -> nits (your mediainfo mastering ~1000 nits)
    def u12_to_nits(u: int) -> float:
        u = max(0, min(4095, int(u)))
        return (u / 4095.0) * 1000.0

    max_pq = []
    avg_pq = []
    missing = 0
    invalid = 0

    # Use a tiny floor so we never plot exactly 0 (keeps fills stable)
    floor_pq = nits_to_pq(0.01)

    for p in entries:
        if p is None:
            missing += 1
            max_pq.append(floor_pq)
            avg_pq.append(floor_pq)
            continue

        dec = _extract_hdrvivid_fields_from_t35(p)
        if not dec:
            invalid += 1
            max_pq.append(floor_pq)
            avg_pq.append(floor_pq)
            continue

        max_nits = u12_to_nits(dec["max12"])
        avg_nits = u12_to_nits(dec["avg12"])

        max_pq.append(nits_to_pq(max_nits))
        avg_pq.append(nits_to_pq(avg_nits))

    # Stats computed in nits (ignore floor placeholders if possible)
    valid_max_nits = [pq_to_nits(v) for v in max_pq if v > nits_to_pq(0.02)]
    valid_avg_nits = [pq_to_nits(v) for v in avg_pq if v > nits_to_pq(0.02)]

    maxcll = max(valid_max_nits) if valid_max_nits else 0.01
    maxcll_avg = (sum(valid_max_nits) / len(valid_max_nits)) if valid_max_nits else 0.01
    maxfall = max(valid_avg_nits) if valid_avg_nits else 0.01
    maxfall_avg = (sum(valid_avg_nits) / len(valid_avg_nits)) if valid_avg_nits else 0.01

    x = list(range(n))

    # 3000x1200 like the Rust/plotters output
    fig = plt.figure(figsize=(30.0, 12.0), dpi=100)
    ax = fig.add_subplot(111)

    ax.set_title("HDR Vivid (CUVA) Luminance Plot", fontsize=22, pad=24)

    # PQ axis: 0..1, but label in nits
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("frames", fontsize=14)
    ax.set_ylabel("nits (cd/m²)", fontsize=14)

    # Mesh similar feel: bold-ish major, very light minor
    ax.grid(True, which="major", alpha=0.10, linewidth=1.2)
    ax.grid(True, which="minor", alpha=0.03, linewidth=0.8)
    ax.minorticks_on()

    # Same keypoints as your Rust code (nits -> PQ ticks, labels show nits)
    key_nits = [
        0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0,
        200.0, 400.0, 600.0, 1000.0, 2000.0, 4000.0, 10000.0
    ]
    key_pq = [nits_to_pq(v) for v in key_nits]
    ax.set_yticks(key_pq)
    ax.set_yticklabels([("{:.3f}".format(v)).rstrip("0").rstrip(".") for v in key_nits], fontsize=11)

    # Labels
    max_label = f"Maximum (MaxCLL: {maxcll:.2f} nits, avg: {maxcll_avg:.2f} nits)"
    avg_label = f"Average (MaxFALL: {maxfall:.2f} nits, avg: {maxfall_avg:.2f} nits)"

    # Two area series (Maximum behind, Average on top)
    ax.fill_between(x, max_pq, 0.0, alpha=0.25, linewidth=0.0, color=MAXSCL_COLOR)
    ax.plot(x, max_pq, linewidth=1.5, color=MAXSCL_COLOR, label=max_label)

    ax.fill_between(x, avg_pq, 0.0, alpha=0.50, linewidth=0.0, color=AVERAGE_COLOR)
    ax.plot(x, avg_pq, linewidth=1.5, color=AVERAGE_COLOR, label=avg_label)

    # Legend lower-left, boxed
    leg = ax.legend(loc="lower left", framealpha=1.0, fontsize=12)
    leg.get_frame().set_linewidth(1.0)

    # Top-left captions (like plotters draw_text at (60,35) etc.)
    caption1 = f"{bin_name}"
    caption2 = f"Entries: {n}. Missing entries: {missing}. Invalid payloads: {invalid}."
    caption3 = "Scale: 4095 -> 1000 nits. Peak source: CUVA max12/avg12 fields."

    fig.text(0.06, 0.94, caption1, fontsize=12, ha="left", va="top")
    fig.text(0.06, 0.92, caption2, fontsize=12, ha="left", va="top")
    fig.text(0.06, 0.90, caption3, fontsize=12, ha="left", va="top")

    # Similar margins to Rust example
    fig.subplots_adjust(left=0.06, right=0.99, top=0.88, bottom=0.10)

    fig.savefig(path_png)
    plt.close(fig)

# ----------------------------
# Commands
# ----------------------------
def cmd_info(args):
    data = read_file_with_progress_scaled(args.input, args.io_chunk, 0.0, 30.0)
    nals = parse_nals_fast(data)
    au_map = compute_au_map(nals)
    if all(x == -1 for x in au_map):
        raise SystemExit("ERROR: No AUD (NAL 35). An AUD is required to delimit Access Units (AUs).")

    total = len(nals) if len(nals) else 1
    last = -1.0
    for idx, n in enumerate(nals):
        if n.nal_type in (39, 40):
            rbsp = remove_emulation_prevention(n.nal[2:])
            _ = parse_sei_messages(rbsp)
        pct = 30.0 + (idx + 1) * 70.0 / total
        if pct - last >= 0.1 or pct >= 100.0:
            progress_bar(pct)
            last = pct
    progress_done()

def cmd_extract(args):
    data = read_file_with_progress_scaled(args.input, args.io_chunk, 0.0, 30.0)
    nals = parse_nals_fast(data)
    au_map = compute_au_map(nals)
    if all(x == -1 for x in au_map):
        raise SystemExit("ERROR: No AUD (NAL 35). An AUD is required to delimit Access Units (AUs).")

    total_aus = max(au_map) + 1
    payload_by_au: List[Optional[bytes]] = [None] * total_aus

    total = len(nals) if len(nals) else 1
    last = -1.0
    for idx, n in enumerate(nals):
        if n.nal_type in (39, 40):
            rbsp = remove_emulation_prevention(n.nal[2:])
            for m in parse_sei_messages(rbsp):
                if m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload):
                    au = au_map[idx]
                    if au >= 0 and payload_by_au[au] is None:
                        payload_by_au[au] = m.payload
        pct = 30.0 + (idx + 1) * 30.0 / total
        if pct - last >= 0.1 or pct >= 60.0:
            progress_bar(pct)
            last = pct

    write_bin(args.output, payload_by_au, 60.0, 100.0)
    progress_done()

def cmd_remove(args):
    data = read_file_with_progress_scaled(args.input, args.io_chunk, 0.0, 30.0)
    nals = parse_nals_fast(data)
    au_map = compute_au_map(nals)
    if all(x == -1 for x in au_map):
        raise SystemExit("ERROR: No AUD (NAL 35). An AUD is required to delimit Access Units (AUs).")

    out = bytearray()
    total = len(nals) if len(nals) else 1
    last = -1.0
    for idx, n in enumerate(nals):
        if n.nal_type not in (39, 40):
            out.extend(data[n.start:n.end])
        else:
            rbsp = remove_emulation_prevention(n.nal[2:])
            msgs = parse_sei_messages(rbsp)
            kept: List[SeiMessage] = []
            for m in msgs:
                if m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload):
                    pass
                else:
                    kept.append(SeiMessage(m.payload_type, m.payload, m.truncated))
            if kept:
                out.extend(build_sei_prefix_nal(kept))

        pct = 30.0 + (idx + 1) * 60.0 / total
        if pct - last >= 0.1 or pct >= 90.0:
            progress_bar(pct)
            last = pct

    write_bytes_with_progress(args.output, out, 90.0, 100.0, args.io_chunk)
    progress_done()

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

def cmd_inject(args):
    # NO bar for BIN parsing
    print("Parsing BIN file...")
    bin_entries = read_bin_all(args.bin)
    if not bin_entries:
        raise SystemExit("ERROR: Empty or invalid BIN file.")
    for p in bin_entries:
        if p is not None and not is_hdrvivid_t35(p):
            raise SystemExit("ERROR: BIN contains non-HDRVivid payload(s) (incorrect cc/pc).")

    # BAR #1: video processing
    print("Processing input video for frame order info...")
    data = read_file_with_progress_scaled(args.input, args.io_chunk, 0.0, 70.0)

    nals = parse_nals_fast(data)
    au_map = compute_au_map(nals)
    if all(x == -1 for x in au_map):
        raise SystemExit("ERROR: No AUD (NAL 35). An AUD is required to delimit Access Units (AUs).")
    au_count = (max(au_map) + 1) if au_map else 0

    total_n = len(nals) if len(nals) else 1
    last = -1.0
    for i, n in enumerate(nals):
        if n.nal_type in (39, 40):
            rbsp = remove_emulation_prevention(n.nal[2:])
            _ = parse_sei_messages(rbsp)
        pct = 70.0 + (i + 1) * 30.0 / total_n
        if pct - last >= 0.1 or pct >= 100.0:
            progress_bar(pct)
            last = pct
    progress_done()

    if len(bin_entries) != au_count:
        sys.stderr.write(f"\nWarning: mismatched lengths. video {au_count}, BIN {len(bin_entries)}\n")
        if len(bin_entries) < au_count:
            sys.stderr.write("Metadata will be duplicated at the end to match video length\n")
        else:
            sys.stderr.write("Metadata will be skipped at the end to match video length\n")
        sys.stderr.flush()

    payloads_by_au = normalize_bin_to_au_count_cycle(bin_entries, au_count)

    # BAR #2: rewrite/inject
    print("Rewriting file with interleaved HDR Vivid SEI NALs..")

    nals_in_au = defaultdict(list)
    for nal_index in range(len(nals)):
        nals_in_au[au_map[nal_index]].append(nal_index)

    replace_nal_bytes: Dict[int, Optional[bytes]] = {}
    insert_before_nal: Dict[int, List[bytes]] = defaultdict(list)

    # Plan edits (0..35)
    total_aus = au_count if au_count else 1
    last = -1.0
    for au in range(au_count):
        pld = payloads_by_au[au]
        indices = nals_in_au.get(au, [])

        if pld is None or not indices:
            pct = (au + 1) * 35.0 / total_aus
            if pct - last >= 0.1 or pct >= 35.0:
                progress_bar(pct)
                last = pct
            continue

        # Replace existing HDRVivid if present
        replaced_this_au = False
        for idx in indices:
            nn = nals[idx]
            if nn.nal_type not in (39, 40):
                continue
            rbsp = remove_emulation_prevention(nn.nal[2:])
            msgs = parse_sei_messages(rbsp)

            has_match = any(m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload) for m in msgs)
            if not has_match:
                continue

            new_msgs: List[SeiMessage] = []
            done = False
            for m in msgs:
                if (not done) and m.payload_type == HDRVIVID_SEI_PT and is_hdrvivid_t35(m.payload):
                    new_msgs.append(SeiMessage(HDRVIVID_SEI_PT, pld, False))
                    done = True
                else:
                    new_msgs.append(SeiMessage(m.payload_type, m.payload, m.truncated))
            replace_nal_bytes[idx] = build_sei_prefix_nal(new_msgs)
            replaced_this_au = True
            break

        if not replaced_this_au:
            # Append into existing SEI_PREFIX in AU
            appended = False
            for idx in indices:
                nn = nals[idx]
                if nn.nal_type != 39:
                    continue
                rbsp = remove_emulation_prevention(nn.nal[2:])
                msgs = parse_sei_messages(rbsp)
                new_msgs = [SeiMessage(m.payload_type, m.payload, m.truncated) for m in msgs]
                new_msgs.append(SeiMessage(HDRVIVID_SEI_PT, pld, False))
                replace_nal_bytes[idx] = build_sei_prefix_nal(new_msgs)
                appended = True
                break

            if not appended:
                vcl_idx = first_vcl_in_au(nals, au_map, au)
                if vcl_idx is None:
                    vcl_idx = indices[0]
                sei = build_sei_prefix_nal([SeiMessage(HDRVIVID_SEI_PT, pld, False)])
                insert_before_nal[vcl_idx].append(sei)

        pct = (au + 1) * 35.0 / total_aus
        if pct - last >= 0.1 or pct >= 35.0:
            progress_bar(pct)
            last = pct

    # Rewrite stream (35..80)
    out = bytearray()
    total_nals2 = len(nals) if len(nals) else 1
    last = -1.0
    for i, nn in enumerate(nals):
        if i in insert_before_nal:
            for blob in insert_before_nal[i]:
                out.extend(blob)

        if i in replace_nal_bytes:
            blob = replace_nal_bytes[i]
            if blob is not None:
                out.extend(blob)
        else:
            out.extend(data[nn.start:nn.end])

        pct = 35.0 + (i + 1) * 45.0 / total_nals2
        if pct - last >= 0.1 or pct >= 80.0:
            progress_bar(pct)
            last = pct

    # Write output (80..100)
    write_bytes_with_progress(args.output, out, 80.0, 100.0, args.io_chunk)
    progress_done()


# ----------------------------
# CLI
# ----------------------------
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

    sp = sub.add_parser("extract", help="Extract HDR Vivid to BIN (progress bar only)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("-o", "--output", required=True, help="Output .bin")
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser("remove", help="Remove HDR Vivid metadata (progress bar only)")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("-o", "--output", required=True, help="Output .hevc")
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("inject", help="Inject/replace HDR Vivid from BIN (two bars, BIN parse has no bar)")
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

