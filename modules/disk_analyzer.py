"""
modules/disk_analyzer.py
Structural analysis of disk images to detect encrypted partitions.
Reads GPT/MBR partition tables and LUKS1/LUKS2 headers without decrypting any data.
Optional pytsk3 integration for deeper filesystem enumeration.
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

# LUKS1 magic: "LUKS" + 0xBA 0xBE, followed by version 0x00 0x01
LUKS_MAGIC   = b"LUKS\xba\xbe"
LUKS1_VERSION = b"\x00\x01"
LUKS2_VERSION = b"\x00\x02"

# GPT signature
GPT_SIGNATURE = b"EFI PART"

# Known encrypted / sensitive partition labels
SENSITIVE_LABELS = {
    "tailsdata":  ("Tails OS persistent encrypted storage", "HIGH"),
    "luks":       ("Generic LUKS encrypted volume",         "HIGH"),
    "cryptdata":  ("Encrypted data partition",              "HIGH"),
    "swap":       ("Swap partition – may contain sensitive memory artifacts", "MEDIUM"),
    "esp":        ("EFI System Partition",                  "LOW"),
    "boot":       ("Boot partition",                        "LOW"),
}


@dataclass
class PartitionEntry:
    index:          int
    type_guid:      str
    partition_guid: str
    start_lba:      int
    end_lba:        int
    label:          str
    size_mb:        float
    has_luks_header: bool  = False
    luks_version:   str    = ""    # "LUKS1" | "LUKS2" | ""
    risk_label:     str    = "NONE"
    risk_note:      str    = ""


@dataclass
class DiskAnalysisResult:
    image_path:            str
    has_gpt:               bool                   = False
    has_mbr:               bool                   = False
    partitions:            list[PartitionEntry]   = field(default_factory=list)
    encrypted_partitions:  list[PartitionEntry]   = field(default_factory=list)
    tails_data_found:      bool                   = False
    error_message:         Optional[str]          = None
    notes:                 list[str]              = field(default_factory=list)

    @property
    def encryption_detected(self) -> bool:
        return bool(self.encrypted_partitions)


# ── Public entry-point ────────────────────────────────────────────────────────

def analyze_disk(image_path: str) -> DiskAnalysisResult:
    """
    Non-destructively inspect a disk image for partition structure
    and encrypted storage markers.
    """
    result = DiskAnalysisResult(image_path=image_path)

    if not os.path.isfile(image_path):
        result.error_message = f"Image not found: {image_path}"
        return result

    try:
        with open(image_path, "rb") as fh:
            _parse_disk(fh, result)
    except PermissionError as exc:
        result.error_message = f"Permission denied reading image: {exc}"
    except Exception as exc:
        result.error_message = f"Unexpected error: {exc}"

    return result


# ── Core parser ───────────────────────────────────────────────────────────────

def _parse_disk(fh, result: DiskAnalysisResult) -> None:
    # ── GPT detection (LBA 1 starts at byte 512) ─────────────────────────
    fh.seek(512)
    if fh.read(8) == GPT_SIGNATURE:
        result.has_gpt = True
        result.notes.append("GPT partition table detected")
        _parse_gpt(fh, result)
        return

    # ── MBR detection ─────────────────────────────────────────────────────
    fh.seek(0)
    mbr = fh.read(512)
    if len(mbr) == 512 and mbr[510:512] == b"\x55\xAA":
        result.has_mbr = True
        result.notes.append("MBR partition table detected")
        _parse_mbr(fh, mbr, result)
        return

    result.notes.append("No recognisable partition table found (raw/unknown format)")


# ── GPT parsing ───────────────────────────────────────────────────────────────

def _parse_gpt(fh, result: DiskAnalysisResult) -> None:
    fh.seek(512)
    header = fh.read(92)
    if len(header) < 92:
        return

    try:
        partition_entry_lba = struct.unpack_from("<Q", header, 72)[0]
        num_entries         = struct.unpack_from("<I", header, 80)[0]
        entry_size          = struct.unpack_from("<I", header, 84)[0]
    except struct.error:
        result.notes.append("Could not parse GPT header fields")
        return

    num_entries = min(num_entries, 128)
    fh.seek(partition_entry_lba * 512)

    for i in range(num_entries):
        raw = fh.read(entry_size)
        if len(raw) < 128:
            break
        entry = _parse_gpt_entry(raw, i)
        if entry is None:
            continue

        result.partitions.append(entry)
        lba_offset = entry.start_lba * 512
        luks_ver = _check_luks_header(fh, lba_offset)
        if luks_ver:
            entry.has_luks_header = True
            entry.luks_version = luks_ver
        _classify_partition(entry, result)


def _parse_gpt_entry(raw: bytes, index: int) -> Optional[PartitionEntry]:
    try:
        type_guid = _format_guid(raw[0:16])
        part_guid = _format_guid(raw[16:32])
        start_lba = struct.unpack_from("<Q", raw, 32)[0]
        end_lba   = struct.unpack_from("<Q", raw, 40)[0]
    except struct.error:
        return None

    if type_guid == "00000000-0000-0000-0000-000000000000":
        return None

    try:
        label = raw[56:128].decode("utf-16-le").rstrip("\x00").strip()
    except UnicodeDecodeError:
        label = ""

    size_mb = max((end_lba - start_lba + 1) * 512 / (1024 ** 2), 0)
    return PartitionEntry(
        index=index + 1,
        type_guid=type_guid,
        partition_guid=part_guid,
        start_lba=start_lba,
        end_lba=end_lba,
        label=label,
        size_mb=round(size_mb, 2),
    )


# ── MBR parsing ───────────────────────────────────────────────────────────────

def _parse_mbr(fh, mbr: bytes, result: DiskAnalysisResult) -> None:
    for i in range(4):
        offset     = 446 + i * 16
        entry_bytes = mbr[offset: offset + 16]
        if len(entry_bytes) < 16:
            break

        partition_type = entry_bytes[4]
        if partition_type == 0:
            continue

        start_lba    = struct.unpack_from("<I", entry_bytes, 8)[0]
        size_sectors = struct.unpack_from("<I", entry_bytes, 12)[0]
        size_mb      = round(size_sectors * 512 / (1024 ** 2), 2)
        type_name    = _mbr_type_name(partition_type)

        entry = PartitionEntry(
            index=i + 1,
            type_guid=f"0x{partition_type:02X}",
            partition_guid="",
            start_lba=start_lba,
            end_lba=start_lba + size_sectors - 1,
            label=type_name,
            size_mb=size_mb,
        )

        luks_ver = _check_luks_header(fh, start_lba * 512)
        if luks_ver:
            entry.has_luks_header = True
            entry.luks_version = luks_ver
        _classify_partition(entry, result)
        result.partitions.append(entry)


# ── LUKS header probe ─────────────────────────────────────────────────────────

def _check_luks_header(fh, byte_offset: int) -> str:
    """
    Return "LUKS1", "LUKS2", or "" based on the header at byte_offset.
    Distinguishes LUKS1 from LUKS2 by reading the 2-byte version field
    at offset +6 after the magic bytes.
    """
    try:
        fh.seek(byte_offset)
        header = fh.read(8)   # 6 magic + 2 version
        if len(header) < 8:
            return ""
        if header[:6] != LUKS_MAGIC:
            return ""
        version_bytes = header[6:8]
        if version_bytes == LUKS2_VERSION:
            return "LUKS2"
        if version_bytes == LUKS1_VERSION:
            return "LUKS1"
        # Magic matches but unrecognised version – still flag it
        return "LUKS(unknown version)"
    except OSError:
        return ""


# ── Partition classification ──────────────────────────────────────────────────

def _classify_partition(entry: PartitionEntry, result: DiskAnalysisResult) -> None:
    label_lower = entry.label.lower()

    if entry.has_luks_header:
        ver_tag = f" ({entry.luks_version})" if entry.luks_version else ""
        entry.risk_label = "HIGH"
        entry.risk_note  = f"LUKS encryption header detected{ver_tag}"
        result.encrypted_partitions.append(entry)
        result.notes.append(
            f"Partition {entry.index} ({entry.label!r}): "
            f"LUKS header found{ver_tag}"
        )

    for keyword, (note, risk) in SENSITIVE_LABELS.items():
        if keyword in label_lower:
            if not entry.has_luks_header:
                entry.risk_label = risk
                entry.risk_note  = note
                if risk == "HIGH":
                    result.encrypted_partitions.append(entry)
            if keyword == "tailsdata":
                result.tails_data_found = True
                result.notes.append(
                    "TailsData partition detected – Tails persistent storage"
                )
            break


# ── Utilities ─────────────────────────────────────────────────────────────────

def _format_guid(raw: bytes) -> str:
    if len(raw) < 16:
        return "00000000-0000-0000-0000-000000000000"
    p1 = struct.unpack_from("<I", raw, 0)[0]
    p2 = struct.unpack_from("<H", raw, 4)[0]
    p3 = struct.unpack_from("<H", raw, 6)[0]
    p4 = raw[8:10].hex()
    p5 = raw[10:16].hex()
    return f"{p1:08X}-{p2:04X}-{p3:04X}-{p4.upper()}-{p5.upper()}"


def _mbr_type_name(t: int) -> str:
    types = {
        0x07: "NTFS/exFAT",    0x0B: "FAT32",
        0x0C: "FAT32 (LBA)",   0x82: "Linux Swap",
        0x83: "Linux",         0x8E: "Linux LVM",
        0xFD: "Linux RAID",    0xEE: "GPT Protective MBR",
        0xEF: "EFI System",
    }
    return types.get(t, f"Type-0x{t:02X}")
