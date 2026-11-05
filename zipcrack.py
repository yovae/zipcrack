#!/usr/bin/env python3
"""高速爆破传统 ZipCrypto 密码。

不带参数运行时会打开图形界面 (zipcrack_gui)。

示例:
  python zipcrack.py            打开图形界面
  python zipcrack.py test.zip
  python zipcrack.py test.zip -c digits --min 1 --max 8
  python zipcrack.py test.zip -c lowerdigit --min 6 --max 6 -j 32
  python zipcrack.py test.zip -w wordlist.txt
  python zipcrack.py test.zip --prefix admin -c digits --min 2 --max 4
  python zipcrack.py --self-test
"""

from __future__ import annotations

import argparse
import ctypes
import multiprocessing as mp
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile
import zlib
from multiprocessing.sharedctypes import RawValue

NATIVE_VERSION = 1
CHUNK = 1_000_000
MAX_U64 = (1 << 64) - 1
ROOT = os.path.dirname(os.path.abspath(__file__))
DLL_PATH = os.path.join(ROOT, "zipcrack_native.dll")
SRC_PATH = os.path.join(ROOT, "zipcrack_native.c")

INIT_KEYS = (305419896, 591751049, 878082192)

PRESETS = {
    "digits": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lowerdigit": "0123456789abcdefghijklmnopqrstuvwxyz",
    "alnum": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "hex": "0123456789abcdef",
    "printable": "".join(chr(c) for c in range(32, 127)),
}

ALIASES = {
    "d": "digits",
    "digit": "digits",
    "num": "digits",
    "numeric": "digits",
    "l": "lower",
    "u": "upper",
    "lower+digit": "lowerdigit",
    "lower+digits": "lowerdigit",
    "alnumlower": "lowerdigit",
    "mix": "alnum",
}

AUTO_MAX = {
    "digits": 8,
    "lower": 6,
    "upper": 6,
    "hex": 8,
    "lowerdigit": 5,
    "alpha": 5,
    "alnum": 4,
    "printable": 3,
}

COMMON = """
123456 123456789 12345678 1234567890 1234567 12345 1234 123 111111 000000
666666 888888 999999 555555 222222 333333 444444 777777 11111111 00000000
88888888 66666666 123123 123321 112233 654321 987654321 0123456789
qwerty qwerty123 qwertyuiop asdfgh asdfghjkl zxcvbn zxcvbnm 1qaz2wsx
1q2w3e4r 1q2w3e4r5t qazwsx qwe123 qwer1234 123qwe abc123 123abc a123456
123456a aa123456 abc123456 abcd1234 password password123 pass pass123
passw0rd p@ssw0rd P@ssw0rd P@ss1234 Password1 Password123 admin admin123
admin888 admin666 admin123456 admin@123 Admin123 Admin@123 root root123
root@123 test test123 test@123 guest guest123 user user123 demo demo123
q1w2e3r4 zaq12wsx 1q2w3e qweasd 5201314 1314520 520520 521521 201314
7758258 147258369 159357 11223344 12344321 woaini iloveyou letmein welcome
monkey dragon master login shadow sunshine trustno1 football princess
654321 666888 888666 168168 101010 121212 321654 789456 147258 258369
135790 246810 112358 11235813 314159 secret zip zip123 123zip testzip
a123456789 abc888 aaa111 111222 qweasdzxc 147369 369258
""".split()


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def progress(msg: str) -> None:
    sys.stderr.write("\r" + msg + " " * 12)
    sys.stderr.flush()


def end_progress() -> None:
    sys.stderr.write("\n")
    sys.stderr.flush()


def fmt_num(n: float) -> str:
    n = int(n)
    if n >= 100_000_000:
        return f"{n / 100_000_000:.2f}亿"
    if n >= 10_000:
        return f"{n / 10_000:.2f}万"
    return str(n)


def make_crc_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        table.append(c & 0xFFFFFFFF)
    return tuple(table)


CRC_TABLE = make_crc_table()


def manual_crc(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def update_keys(k0: int, k1: int, k2: int, b: int) -> tuple[int, int, int]:
    k0 = CRC_TABLE[(k0 ^ b) & 0xFF] ^ (k0 >> 8)
    k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
    k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
    k2 = CRC_TABLE[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
    return k0, k1, k2


def apply_bytes(keys: tuple[int, int, int], data: bytes) -> tuple[int, int, int]:
    k0, k1, k2 = keys
    for b in data:
        k0, k1, k2 = update_keys(k0, k1, k2, b)
    return k0, k1, k2


def keystream(k2: int) -> int:
    t = (k2 | 2) & 0xFFFF
    return ((t * (t ^ 1)) >> 8) & 0xFF


def py_check(
    password: bytes,
    cipher: bytes,
    expected_crc: int,
    check_byte: int,
    init_keys: tuple[int, int, int] | None = None,
    suffix: bytes = b"",
) -> bool:
    if len(cipher) < 12:
        return False
    keys = INIT_KEYS if init_keys is None else init_keys
    keys = apply_bytes(keys, password)
    keys = apply_bytes(keys, suffix)
    k0, k1, k2 = keys
    last = 0
    for i in range(12):
        last = cipher[i] ^ keystream(k2)
        k0, k1, k2 = update_keys(k0, k1, k2, last)
    if last != check_byte:
        return False
    crc = 0xFFFFFFFF
    for i in range(12, len(cipher)):
        plain = cipher[i] ^ keystream(k2)
        k0, k1, k2 = update_keys(k0, k1, k2, plain)
        crc = CRC_TABLE[(crc ^ plain) & 0xFF] ^ (crc >> 8)
    crc = (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
    return crc == expected_crc


def zipcrypto_encrypt(data: bytes, password: bytes, crc: int) -> bytes:
    keys = apply_bytes(INIT_KEYS, password)
    k0, k1, k2 = keys
    header = bytes((i * 17) & 0xFF for i in range(11)) + bytes([(crc >> 24) & 0xFF])
    out = bytearray()
    for b in header + data:
        ks = keystream(k2)
        out.append(b ^ ks)
        k0, k1, k2 = update_keys(k0, k1, k2, b)
    return bytes(out)


def make_encrypted_zip(path: str, members: list[tuple[str, bytes]], password: bytes) -> None:
    blobs = []
    centrals = []
    offset = 0
    dos_time = 12 << 11
    dos_date = ((2024 - 1980) << 9) | (1 << 5) | 1
    for name, data in members:
        try:
            name_b = name.encode("ascii")
            flags = 1
        except UnicodeEncodeError:
            name_b = name.encode("utf-8")
            flags = 1 | 0x800
        crc = zlib.crc32(data) & 0xFFFFFFFF
        cipher = zipcrypto_encrypt(data, password, crc)
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            0,
            dos_time,
            dos_date,
            crc,
            len(cipher),
            len(data),
            len(name_b),
            0,
        ) + name_b
        blobs.append(local + cipher)
        centrals.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                flags,
                0,
                dos_time,
                dos_date,
                crc,
                len(cipher),
                len(data),
                len(name_b),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
            + name_b
        )
        offset += len(local) + len(cipher)
    central_blob = b"".join(centrals)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(members),
        len(members),
        len(central_blob),
        offset,
        0,
    )
    with open(path, "wb") as handle:
        handle.write(b"".join(blobs))
        handle.write(central_blob)
        handle.write(eocd)


def find_gcc() -> str | None:
    found = shutil.which("gcc")
    if found:
        return found
    for candidate in (
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def load_lib(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.zipcrack_version.argtypes = []
    lib.zipcrack_version.restype = ctypes.c_int
    lib.check_password.argtypes = [
        u8p,
        ctypes.c_int,
        u8p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_uint8,
    ]
    lib.check_password.restype = ctypes.c_int
    lib.check_batch.argtypes = [
        u8p,
        ctypes.c_int,
        ctypes.c_int,
        u8p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_uint8,
        u8p,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.check_batch.restype = ctypes.c_int
    lib.crack_range.argtypes = [
        u8p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        u8p,
        ctypes.c_int,
        u8p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint64),
        u8p,
    ]
    lib.crack_range.restype = ctypes.c_int
    return lib


def build_dll() -> str | None:
    gcc = find_gcc()
    if gcc is None or not os.path.isfile(SRC_PATH):
        return None
    if os.path.isfile(DLL_PATH) and os.path.getmtime(DLL_PATH) >= os.path.getmtime(SRC_PATH):
        try:
            lib = load_lib(DLL_PATH)
            if lib.zipcrack_version() == NATIVE_VERSION:
                return DLL_PATH
        except OSError:
            pass
    commands = []
    for march in (["-march=native"], []):
        commands.append(
            [gcc, "-O3", *march, "-std=c11", "-Wall", "-shared", "-static-libgcc", "-s", "-o", DLL_PATH, SRC_PATH]
        )
    errors = []
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and os.path.isfile(DLL_PATH):
            return DLL_PATH
        errors.append((result.stdout or "") + (result.stderr or ""))
    log("native 引擎编译失败，改用 Python。")
    if errors:
        log(errors[-1].strip())
    return None


def c_buf(data: bytes) -> ctypes.Array:
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def native_check(lib: ctypes.CDLL, password: bytes, cipher: bytes, crc: int, check: int) -> bool:
    pw = c_buf(password or b"\x00")
    src = c_buf(cipher)
    rc = lib.check_password(
        pw,
        len(password),
        src,
        len(cipher),
        ctypes.c_uint32(crc),
        ctypes.c_uint8(check),
    )
    return rc == 1


def native_batch(lib: ctypes.CDLL, passwords: list[bytes], cipher: bytes, crc: int, check: int) -> bytes | None:
    packed = bytearray()
    usable = []
    for pw in passwords:
        if len(pw) > 256:
            continue
        usable.append(pw)
        packed += struct.pack("<H", len(pw))
        packed += pw
    if not usable:
        return None
    blob = c_buf(bytes(packed))
    src = c_buf(cipher)
    out = (ctypes.c_uint8 * 256)()
    out_len = ctypes.c_int(0)
    rc = lib.check_batch(
        blob,
        len(packed),
        len(usable),
        src,
        len(cipher),
        ctypes.c_uint32(crc),
        ctypes.c_uint8(check),
        out,
        ctypes.byref(out_len),
    )
    if rc != 1:
        return None
    return bytes(out[: out_len.value])


def native_range(
    lib: ctypes.CDLL,
    charset: bytes,
    length: int,
    start: int,
    count: int,
    init_keys: tuple[int, int, int],
    suffix: bytes,
    cipher: bytes,
    crc: int,
    check: int,
    charset_buf: ctypes.Array | None = None,
    cipher_buf: ctypes.Array | None = None,
    suffix_buf: ctypes.Array | None = None,
) -> tuple[bytes | None, int]:
    if charset_buf is None:
        charset_buf = c_buf(charset)
    if cipher_buf is None:
        cipher_buf = c_buf(cipher)
    if suffix:
        suffix_ptr = suffix_buf if suffix_buf is not None else c_buf(suffix)
    else:
        suffix_ptr = None
    out = (ctypes.c_uint8 * length)()
    tested = ctypes.c_uint64(0)
    rc = lib.crack_range(
        charset_buf,
        len(charset),
        length,
        ctypes.c_uint64(start),
        ctypes.c_uint64(count),
        ctypes.c_uint32(init_keys[0]),
        ctypes.c_uint32(init_keys[1]),
        ctypes.c_uint32(init_keys[2]),
        suffix_ptr,
        len(suffix),
        cipher_buf,
        len(cipher),
        ctypes.c_uint32(crc),
        ctypes.c_uint8(check),
        ctypes.byref(tested),
        out,
    )
    found = bytes(out[:length]) if rc == 1 else None
    return found, int(tested.value)


def py_range(
    charset: bytes,
    length: int,
    start: int,
    count: int,
    init_keys: tuple[int, int, int],
    suffix: bytes,
    cipher: bytes,
    crc: int,
    check: int,
) -> tuple[bytes | None, int]:
    n = len(charset)
    idx = start
    digits = [0] * length
    for i in range(length - 1, -1, -1):
        digits[i] = idx % n
        idx //= n
    tested = 0
    while tested < count:
        pw = bytes(charset[d] for d in digits)
        if py_check(pw, cipher, crc, check, init_keys, suffix):
            return pw, tested + 1
        tested += 1
        pos = length - 1
        while pos >= 0:
            digits[pos] += 1
            if digits[pos] < n:
                break
            digits[pos] = 0
            pos -= 1
        else:
            break
    return None, tested


def index_password(charset: bytes, length: int, index: int) -> bytes:
    n = len(charset)
    chars = [0] * length
    for i in range(length - 1, -1, -1):
        chars[i] = charset[index % n]
        index //= n
    return bytes(chars)


def probe_ok(
    password: bytes,
    probe: tuple[bytes, int, int] | None,
    lib: ctypes.CDLL | None,
) -> bool:
    if probe is None:
        return True
    cipher, crc, check = probe
    if lib is not None:
        return native_check(lib, password, cipher, crc, check)
    return py_check(password, cipher, crc, check)


def _range_worker(
    dll_path: str | None,
    charset: bytes,
    length: int,
    start: int,
    count: int,
    init_keys: tuple[int, int, int],
    suffix: bytes,
    cipher: bytes,
    crc: int,
    check: int,
    prefix: bytes,
    stop_event: mp.synchronize.Event,
    progress_value: ctypes.c_uint64,
    queue: mp.Queue,
    confirm: tuple[bytes, int, int] | None,
) -> None:
    try:
        lib = load_lib(dll_path) if dll_path else None
        charset_buf = c_buf(charset) if lib else None
        cipher_buf = c_buf(cipher) if lib else None
        suffix_buf = c_buf(suffix) if lib and suffix else None
        pos = start
        left = count
        while left > 0 and not stop_event.is_set():
            step = CHUNK if left > CHUNK else left
            if lib:
                found, tested_n = native_range(
                    lib,
                    charset,
                    length,
                    pos,
                    step,
                    init_keys,
                    suffix,
                    cipher,
                    crc,
                    check,
                    charset_buf,
                    cipher_buf,
                    suffix_buf,
                )
            else:
                found, tested_n = py_range(
                    charset, length, pos, step, init_keys, suffix, cipher, crc, check
                )
            if tested_n <= 0:
                break
            progress_value.value += tested_n
            full = prefix + found + suffix if found is not None else None
            pos += tested_n
            left -= tested_n
            if full is not None and probe_ok(full, confirm, lib):
                stop_event.set()
                queue.put(full)
                return
    except Exception:
        queue.put(("err", traceback.format_exc()))


def choose_workers(total: int, requested: int | None) -> int:
    cpus = os.cpu_count() or 1
    if requested and requested > 0:
        n = requested
    elif total < 3_000_000:
        n = 1
    elif total < 20_000_000:
        n = min(8, cpus)
    else:
        n = cpus
    if total < n:
        n = int(total)
    return max(1, n)


def split_ranges(total: int, workers: int) -> list[tuple[int, int]]:
    base = total // workers
    rem = total % workers
    ranges = []
    start = 0
    for i in range(workers):
        count = base + (1 if i < rem else 0)
        if count:
            ranges.append((start, count))
            start += count
    return ranges


def search_charset(
    charset: bytes,
    length: int,
    cipher: bytes,
    crc: int,
    check: int,
    dll_path: str | None,
    init_keys: tuple[int, int, int],
    prefix: bytes = b"",
    suffix: bytes = b"",
    workers: int | None = None,
    deadline: float | None = None,
    label: str = "",
    confirm: tuple[bytes, int, int] | None = None,
    progress_cb=None,
    cancel_event=None,
) -> bytes | None:
    n = len(charset)
    if length <= 0 or n <= 0:
        return None
    total = n ** length
    if total > MAX_U64:
        raise SystemExit(f"长度 {length} 的搜索空间超过 64 位，请缩小字符集或长度。")
    worker_n = choose_workers(total, workers)
    t0 = time.perf_counter()

    def report(tested: int) -> None:
        elapsed = time.perf_counter() - t0
        rate = tested / elapsed if elapsed else 0
        remain = (total - tested) / rate if rate else 0
        if progress_cb is not None:
            progress_cb(tested, total, rate, remain, label, length)
        else:
            progress(
                f"{label} 长度 {length}  已测 {fmt_num(tested)}/{fmt_num(total)}"
                f"  {rate / 1e6:.2f} M/s  剩余 {remain:.1f}s"
            )

    if worker_n == 1:
        lib = load_lib(dll_path) if dll_path else None
        charset_buf = c_buf(charset) if lib else None
        cipher_buf = c_buf(cipher) if lib else None
        suffix_buf = c_buf(suffix) if lib and suffix else None
        pos = 0
        left = total
        tested = 0
        while left > 0:
            if deadline is not None and time.perf_counter() >= deadline:
                end_progress()
                log("达到超时，停止当前长度。")
                return None
            if cancel_event is not None and cancel_event.is_set():
                end_progress()
                return None
            step = CHUNK if left > CHUNK else left
            if lib:
                found, tested_n = native_range(
                    lib, charset, length, pos, step, init_keys, suffix, cipher, crc, check,
                    charset_buf, cipher_buf, suffix_buf,
                )
            else:
                found, tested_n = py_range(
                    charset, length, pos, step, init_keys, suffix, cipher, crc, check
                )
            if tested_n <= 0:
                break
            tested += tested_n
            report(tested)
            full = prefix + found + suffix if found is not None else None
            pos += tested_n
            left -= tested_n
            if full is not None and probe_ok(full, confirm, lib):
                end_progress()
                return full
        end_progress()
        return None

    ctx = mp.get_context("spawn")
    stop_event = ctx.Event()
    queue: mp.Queue = ctx.Queue()
    ranges = split_ranges(total, worker_n)
    progress_values = [RawValue(ctypes.c_uint64, 0) for _ in ranges]
    procs = []
    for (start, count), raw in zip(ranges, progress_values):
        proc = ctx.Process(
            target=_range_worker,
            args=(
                dll_path,
                charset,
                length,
                start,
                count,
                init_keys,
                suffix,
                cipher,
                crc,
                check,
                prefix,
                stop_event,
                raw,
                queue,
                confirm,
            ),
            daemon=True,
        )
        proc.start()
        procs.append(proc)

    found_pw = None
    timed_out = False
    cancelled = False
    try:
        while any(proc.is_alive() for proc in procs):
            try:
                item = queue.get(timeout=0.25)
            except Exception:
                item = None
            if item is not None:
                if isinstance(item, tuple) and item and item[0] == "err":
                    stop_event.set()
                    raise RuntimeError(item[1])
                found_pw = item
                stop_event.set()
                break
            if deadline is not None and time.perf_counter() >= deadline:
                stop_event.set()
                timed_out = True
                break
            if cancel_event is not None and cancel_event.is_set():
                stop_event.set()
                cancelled = True
                break
            report(sum(int(v.value) for v in progress_values))
    finally:
        stop_event.set()
        for proc in procs:
            proc.join(timeout=5)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=1)
        end_progress()
        try:
            queue.cancel_join_thread()
        except Exception:
            pass
    if found_pw is None:
        try:
            item = queue.get_nowait()
        except Exception:
            item = None
        if isinstance(item, tuple) and item and item[0] == "err":
            raise RuntimeError(item[1])
        if isinstance(item, (bytes, bytearray)):
            found_pw = bytes(item)
    if timed_out:
        log("达到超时，停止当前长度。")
    for proc in procs:
        if proc.exitcode not in (0, None) and found_pw is None and not timed_out and not cancelled:
            raise RuntimeError(f"工作进程异常退出，代码 {proc.exitcode}")
    return found_pw


def search_passwords(
    passwords: list[bytes],
    cipher: bytes,
    crc: int,
    check: int,
    dll_path: str | None,
    label: str,
    confirm: tuple[bytes, int, int] | None = None,
    progress_cb=None,
    cancel_event=None,
) -> bytes | None:
    if not passwords:
        return None
    t0 = time.perf_counter()
    total = len(passwords)
    lib = load_lib(dll_path) if dll_path else None
    batch_size = 20000
    tested = 0
    cursor = 0

    def report() -> None:
        elapsed = time.perf_counter() - t0
        rate = tested / elapsed if elapsed else 0
        remain = (total - tested) / rate if rate else 0
        if progress_cb is not None:
            progress_cb(tested, total, rate, remain, label, 0)
        else:
            progress(f"{label}  已测 {fmt_num(tested)}/{fmt_num(total)}  {rate / 1e6:.2f} M/s")

    while cursor < total:
        if cancel_event is not None and cancel_event.is_set():
            end_progress()
            return None
        window = passwords[cursor : cursor + batch_size]
        if lib:
            found = native_batch(lib, window, cipher, crc, check)
        else:
            found = None
            for pw in window:
                if py_check(pw, cipher, crc, check):
                    found = pw
                    break
        if found is None:
            tested += len(window)
            cursor += len(window)
        else:
            rel = window.index(found)
            tested += rel + 1
            cursor += rel + 1
            if probe_ok(found, confirm, lib):
                report()
                end_progress()
                return found
        report()
    end_progress()
    return None


def has_aes(info: zipfile.ZipInfo) -> bool:
    if info.compress_type == 99:
        return True
    extra = info.extra or b""
    index = 0
    size = len(extra)
    while index + 4 <= size:
        header_id, header_size = struct.unpack_from("<HH", extra, index)
        if header_id == 0x9901:
            return True
        if index + 4 + header_size > size:
            break
        index += 4 + header_size
    return False


def read_cipher(path: str, info: zipfile.ZipInfo) -> tuple[bytes, int, int]:
    with open(path, "rb") as handle:
        handle.seek(info.header_offset)
        header = handle.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise RuntimeError(f"本地文件头无效: {info.filename}")
        name_len, extra_len = struct.unpack_from("<HH", header, 26)
        mtime = struct.unpack_from("<H", header, 10)[0]
        data_off = info.header_offset + 30 + name_len + extra_len
        handle.seek(data_off)
        cipher = handle.read(info.compress_size)
    if len(cipher) != info.compress_size:
        raise RuntimeError(f"加密数据不完整: {info.filename}")
    if info.flag_bits & 0x8:
        check = (mtime >> 8) & 0xFF
    else:
        check = (info.CRC >> 24) & 0xFF
    return cipher, info.CRC & 0xFFFFFFFF, check


def select_target(
    path: str,
) -> tuple[zipfile.ZipInfo, bytes, int, int, tuple[bytes, int, int] | None, list[str]]:
    with zipfile.ZipFile(path) as archive:
        stored = []
        encrypted = 0
        aes = 0
        deflated = []
        for info in archive.infolist():
            if info.is_dir() or not (info.flag_bits & 0x1):
                continue
            if info.file_size <= 0 or info.compress_size < 12:
                continue
            encrypted += 1
            if has_aes(info):
                aes += 1
                continue
            if info.compress_type == 0:
                stored.append(info)
            elif info.compress_type == 8:
                deflated.append(info)
        if encrypted == 0:
            raise SystemExit("压缩包里没有加密文件。")
        if not stored:
            if aes == encrypted:
                raise SystemExit("这是 WinZip AES 加密。这个程序只爆破传统 ZipCrypto。")
            raise SystemExit("没有存储型 ZipCrypto 文件，无法做稳定的高速 CRC 校验。")
        strong = [item for item in stored if item.file_size >= 8]
        pool = strong or stored
        pool.sort(key=lambda item: (item.file_size, item.compress_size))
        target = pool[0]
        confirm_info = pool[1] if len(pool) > 1 else None
        names = [target.filename]
        if confirm_info is not None:
            names.append(confirm_info.filename)
        if deflated:
            deflated.sort(key=lambda item: item.file_size)
            if deflated[0].filename not in names:
                names.append(deflated[0].filename)
    cipher, crc, check = read_cipher(path, target)
    confirm = read_cipher(path, confirm_info) if confirm_info is not None else None
    if target.file_size < 8:
        log("校验文件太短，结果会再用第二个文件复核。")
    return target, cipher, crc, check, confirm, names


def verify_password(path: str, password: bytes, names: list[str]) -> list[str]:
    checked = []
    with zipfile.ZipFile(path) as archive:
        archive.setpassword(password)
        for name in names:
            archive.read(name)
            checked.append(name)
    return checked


def display_password(password: bytes) -> str:
    if password == b"":
        return "(空)"
    for encoding in ("utf-8", "gbk"):
        try:
            text = password.decode(encoding)
        except UnicodeDecodeError:
            continue
        if all(ch.isprintable() for ch in text):
            return text
    return password.hex()


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def archive_seeds(path: str) -> list[str]:
    seeds = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            part = info.filename.replace("\\", "/").split("/", 1)[0]
            if part and part not in seeds:
                seeds.append(part)
            if len(seeds) >= 8:
                break
    enriched = []
    for seed in seeds:
        enriched.append(seed)
        letters = "".join(ch for ch in seed if ch.isalpha())
        digits = "".join(ch for ch in seed if ch.isdigit())
        if letters:
            enriched.append(letters)
        if digits:
            enriched.append(digits)
    more = []
    for seed in enriched:
        more.extend((seed, seed.lower(), seed.upper(), seed.capitalize()))
    return dedupe(more)


def build_common(seeds: list[str]) -> list[bytes]:
    words = list(COMMON)
    for digit in "0123456789":
        words.append(digit * 6)
        words.append(digit * 8)
    suffixes = (
        "", "1", "12", "01", "123", "1234", "12345", "123456",
        "520", "888", "666", "000", "111", "2024", "2025", "2026",
        "@123", "!", "abc", "qwe",
    )
    for seed in seeds:
        for suffix in suffixes:
            words.append(seed + suffix)
            if suffix:
                words.append(suffix + seed)
    encoded = []
    seen = set()
    for word in dedupe(words):
        token = word.encode("utf-8")
        if token in seen or len(token) > 64:
            continue
        seen.add(token)
        encoded.append(token)
    encoded.insert(0, b"")
    return encoded


def parse_charset(spec: str) -> tuple[str, bytes]:
    key = ALIASES.get(spec, spec)
    if key in PRESETS:
        text = PRESETS[key]
        name = key
    else:
        text = spec
        name = "custom"
    chars = []
    seen = set()
    for ch in text:
        if ch in seen:
            continue
        if ord(ch) > 255:
            raise SystemExit("爆破字符集只支持单字节字符。中文密码请使用词表。")
        seen.add(ch)
        chars.append(ch)
    if not chars:
        raise SystemExit("字符集是空的。")
    return name, "".join(chars).encode("latin1")


def resolve_lengths(name: str, charset_len: int, min_len: int | None, max_len: int | None) -> tuple[int, int]:
    auto_max = AUTO_MAX.get(name)
    if auto_max is None:
        if charset_len <= 10:
            auto_max = 8
        elif charset_len <= 26:
            auto_max = 6
        elif charset_len <= 36:
            auto_max = 5
        elif charset_len <= 62:
            auto_max = 4
        else:
            auto_max = 3
    low = 1 if min_len is None else min_len
    high = auto_max if max_len is None else max_len
    if low < 1:
        low = 1
    if high < low:
        raise SystemExit("--max 不能小于 --min。")
    if high > 16:
        raise SystemExit("最大长度不能超过 16。")
    return low, high


def detect_encoding(path: str, preferred: str) -> str:
    with open(path, "rb") as handle:
        sample = handle.read(65536)
    for encoding in (preferred, "utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            sample.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "latin-1"


def load_wordlist(path: str, encoding: str, prefix: str, suffix: str) -> list[bytes]:
    chosen = detect_encoding(path, encoding)
    if chosen != encoding:
        log(f"词表按 {chosen} 读取。")
    passwords = []
    seen = set()
    with open(path, "r", encoding=chosen, errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            full = f"{prefix}{text}{suffix}"
            for enc in (chosen, "utf-8", "gbk"):
                try:
                    token = full.encode(enc)
                except UnicodeEncodeError:
                    continue
                if token in seen or len(token) > 128:
                    continue
                seen.add(token)
                passwords.append(token)
                if enc == chosen or token.isascii():
                    break
    return passwords


def engine_self_check(dll_path: str | None) -> None:
    if manual_crc(b"Hello ZIP\n") != (zlib.crc32(b"Hello ZIP\n") & 0xFFFFFFFF):
        raise RuntimeError("CRC 实现和 zlib 不一致。")
    data = b"Hello ZIP\n"
    password = b"ab12"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    cipher = zipcrypto_encrypt(data, password, crc)
    check = (crc >> 24) & 0xFF
    if not py_check(password, cipher, crc, check) or py_check(b"nope", cipher, crc, check):
        raise RuntimeError("Python ZipCrypto 自检失败。")
    samples = (
        (b"ab", 2, b"aa", 0),
        (b"ab", 2, b"bb", 3),
        (b"ab12", 4, b"ab12", None),
    )
    lib = load_lib(dll_path) if dll_path else None
    if lib is not None:
        if lib.zipcrack_version() != NATIVE_VERSION:
            raise RuntimeError("native 引擎版本不匹配。")
        if not native_check(lib, password, cipher, crc, check) or native_check(lib, b"nope", cipher, crc, check):
            raise RuntimeError("native ZipCrypto 自检失败。")
    for charset, length, expect, index in samples:
        body = b"Z"
        body_crc = zlib.crc32(body) & 0xFFFFFFFF
        body_cipher = zipcrypto_encrypt(body, expect, body_crc)
        body_check = (body_crc >> 24) & 0xFF
        if index is None:
            index = 0
            n = len(charset)
            for i in range(length - 1, -1, -1):
                pass
            idx = 0
            for ch in expect:
                idx = idx * len(charset) + charset.index(ch)
            index = idx
        found_py, _ = py_range(charset, length, 0, len(charset) ** length, INIT_KEYS, b"", body_cipher, body_crc, body_check)
        if found_py != expect:
            raise RuntimeError(f"Python 爆破自检失败，期望 {expect!r}，得到 {found_py!r}")
        if lib is not None:
            found_c, tested = native_range(
                lib, charset, length, 0, len(charset) ** length, INIT_KEYS, b"", body_cipher, body_crc, body_check
            )
            if found_c != expect:
                raise RuntimeError(f"native 爆破自检失败，期望 {expect!r}，得到 {found_c!r}")
            if tested <= index:
                raise RuntimeError("native 测试计数异常。")
    prefixed = apply_bytes(INIT_KEYS, b"X")
    body = b"ok"
    expect = b"99"
    full = b"X99!"
    body_crc = zlib.crc32(body) & 0xFFFFFFFF
    body_cipher = zipcrypto_encrypt(body, full, body_crc)
    body_check = (body_crc >> 24) & 0xFF
    found_py, _ = py_range(b"0123456789", 2, 0, 100, prefixed, b"!", body_cipher, body_crc, body_check)
    if found_py != expect:
        raise RuntimeError("前缀后缀自检失败。")
    if lib is not None:
        found_c, _ = native_range(
            lib, b"0123456789", 2, 0, 100, prefixed, b"!", body_cipher, body_crc, body_check
        )
        if found_c != expect:
            raise RuntimeError("native 前缀后缀自检失败。")


def run_self_test() -> int:
    log("运行完整自检。")
    dll = build_dll()
    engine_self_check(dll)
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        data = b"Hello ZIP\n"
        second = b"second-file!"
        make_encrypted_zip(path, [("note.txt", data), ("b.txt", second)], b"ab12")
        with zipfile.ZipFile(path) as archive:
            archive.setpassword(b"ab12")
            if archive.read("note.txt") != data or archive.read("b.txt") != second:
                raise RuntimeError("标准库无法解开自测压缩包。")
        found = crack_zip(
            path,
            stages=[("charset", "lowerdigit", 4, 4)],
            workers=8,
            deadline=None,
            prefix=b"",
            suffix=b"",
            wordlist=None,
            encoding="utf-8",
            include_common=False,
            dll_path=dll,
        )
        if found != b"ab12":
            raise RuntimeError(f"多进程自检失败，得到 {found!r}")
    finally:
        if path and os.path.exists(path):
            os.remove(path)
    log("自检通过。")
    return 0


def crack_zip(
    path: str,
    stages: list[tuple],
    workers: int | None,
    deadline: float | None,
    prefix: bytes,
    suffix: bytes,
    wordlist: str | None,
    encoding: str,
    include_common: bool,
    dll_path: str | None,
    progress_cb=None,
    log_cb=None,
    cancel_event=None,
) -> bytes | None:
    def emit(msg: str) -> None:
        if log_cb is not None:
            log_cb(msg)
        else:
            log(msg)

    def cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    target, cipher, crc, check, confirm, names = select_target(path)
    engine = "native" if dll_path else "python"
    emit(
        f"引擎: {engine}  校验文件: {target.filename}  "
        f"明文 {target.file_size} 字节  密文 {target.compress_size} 字节  "
        f"复核 {len(names)} 个文件  进程上限 {workers or os.cpu_count()}"
    )
    init_keys = apply_bytes(INIT_KEYS, prefix)

    def accept(found: bytes | None) -> bytes | None:
        if found is None:
            return None
        try:
            verify_password(path, found, names)
        except RuntimeError as exc:
            emit(f"候选口令未能解开全部复核文件: {exc}")
            return None
        return found

    if include_common:
        passwords = build_common(archive_seeds(path))
        if prefix or suffix:
            passwords = [prefix + item + suffix for item in passwords if len(prefix) + len(item) + len(suffix) <= 128]
        emit(f"先试 {len(passwords)} 条常见口令。")
        found = accept(search_passwords(passwords, cipher, crc, check, dll_path, "常见口令", confirm, progress_cb, cancel_event))
        if found is not None:
            return found
        if cancelled():
            return None
    if wordlist:
        passwords = load_wordlist(wordlist, encoding, "", "")
        if prefix or suffix:
            passwords = [prefix + item + suffix for item in passwords]
        emit(f"词表 {len(passwords)} 条。")
        found = accept(search_passwords(passwords, cipher, crc, check, dll_path, "词表", confirm, progress_cb, cancel_event))
        if found is not None:
            return found
        if cancelled():
            return None
    for stage in stages:
        kind = stage[0]
        if kind != "charset":
            continue
        _, name, min_len, max_len = stage
        charset_name, charset = parse_charset(name)
        low, high = resolve_lengths(charset_name, len(charset), min_len, max_len)
        for length in range(low, high + 1):
            if deadline is not None and time.perf_counter() >= deadline:
                emit("达到超时，停止。")
                return None
            if cancelled():
                return None
            total = len(charset) ** length
            emit(f"开始 {charset_name} 长度 {length}，空间 {fmt_num(total)}。")
            found = accept(
                search_charset(
                    charset,
                    length,
                    cipher,
                    crc,
                    check,
                    dll_path,
                    init_keys,
                    prefix,
                    suffix,
                    workers,
                    deadline,
                    charset_name,
                    confirm,
                    progress_cb,
                    cancel_event,
                )
            )
            if found is not None:
                return found
            if cancelled():
                return None
    return None


def default_stages() -> list[tuple]:
    return [
        ("charset", "digits", 1, 8),
        ("charset", "lower", 1, 6),
        ("charset", "lowerdigit", 1, 5),
    ]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="高速爆破传统 ZipCrypto 密码。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "默认会先试常见口令和压缩包名称，再爆破数字 1-8 位、"
            "小写 1-6 位、小写+数字 1-5 位。\n"
            "字符集: digits lower upper alpha lowerdigit alnum hex printable，"
            "也可以直接写自定义字符。"
        ),
    )
    parser.add_argument("zip_path", nargs="?", help="加密 zip 文件")
    parser.add_argument("-c", "--charset", help="字符集预设或自定义字符")
    parser.add_argument("--min", dest="min_len", type=int, help="最小长度")
    parser.add_argument("--max", dest="max_len", type=int, help="最大长度")
    parser.add_argument("-w", "--wordlist", help="词表文件，一行一个密码")
    parser.add_argument("--prefix", default="", help="密码前缀")
    parser.add_argument("--suffix", default="", help="密码后缀")
    parser.add_argument("--encoding", default="utf-8", help="词表和前后缀编码，默认 utf-8")
    parser.add_argument("-j", "--workers", type=int, default=0, help="进程数，默认按搜索空间自动选择")
    parser.add_argument("--timeout", type=float, default=0, help="总超时秒数，0 表示不限制")
    parser.add_argument("--common", action="store_true", help="额外尝试常见口令")
    parser.add_argument("--no-common", action="store_true", help="跳过常见口令")
    parser.add_argument("--self-test", action="store_true", help="用已知密码做完整自检")
    parser.add_argument("--gui", action="store_true", help="打开图形界面")
    return parser.parse_args(argv)


def launch_gui() -> int:
    try:
        from zipcrack_gui import main as gui_main
    except Exception as exc:
        log(f"图形界面启动失败 ({exc})，改用命令行。")
        parse_args(["-h"])
        return 2
    return gui_main()


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    if not raw:
        return launch_gui()
    args = parse_args(raw)
    if args.gui:
        return launch_gui()
    if args.self_test:
        return run_self_test()
    if not args.zip_path:
        parse_args(["-h"])
        return 2
    path = os.path.abspath(args.zip_path)
    if not os.path.isfile(path):
        log(f"找不到文件: {path}")
        return 2
    dll = build_dll()
    engine_self_check(dll)
    try:
        prefix = args.prefix.encode(args.encoding)
        suffix = args.suffix.encode(args.encoding)
    except UnicodeEncodeError:
        log("前后缀无法按指定编码转换成字节。")
        return 2
    if args.charset:
        stages = [("charset", args.charset, args.min_len, args.max_len)]
        include_common = args.common and not args.no_common
    else:
        stages = [] if args.wordlist and not args.common else default_stages()
        if args.wordlist and not args.common:
            stages = []
        include_common = not args.no_common
    deadline = time.perf_counter() + args.timeout if args.timeout and args.timeout > 0 else None
    started = time.perf_counter()
    try:
        found = crack_zip(
            path,
            stages=stages,
            workers=args.workers or None,
            deadline=deadline,
            prefix=prefix,
            suffix=suffix,
            wordlist=args.wordlist,
            encoding=args.encoding,
            include_common=include_common,
            dll_path=dll,
        )
    except KeyboardInterrupt:
        end_progress()
        log("已停止。")
        return 130
    elapsed = time.perf_counter() - started
    if found is None:
        log(f"未找到密码。耗时 {elapsed:.1f}s")
        if not args.charset and not args.wordlist:
            log("默认空间已经跑完。可以继续缩小范围，例如:")
            log(f"  python zipcrack.py {args.zip_path} -c lowerdigit --min 6 --max 6")
            log(f"  python zipcrack.py {args.zip_path} -c alnum --min 1 --max 4")
            log(f"  python zipcrack.py {args.zip_path} -w wordlist.txt")
        return 1
    log(f"耗时 {elapsed:.1f}s")
    print(f"密码: {display_password(found)}")
    if not found.isascii():
        print(f"密码十六进制: {found.hex()}")
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
