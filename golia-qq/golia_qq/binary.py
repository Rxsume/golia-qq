"""Binary packet reader/writer (big-endian), mirroring Lagrange's BinaryPacket.

Semantics (from Lagrange.Core/Utility/Binary/BinaryPacket.cs):
- All integers are big-endian.
- Write(bytes, prefix): prefix byte count = low 3 bits of flag (1/2/4);
  if WithPrefix (0x08) is set, the length value includes the prefix itself.
  LengthOnly (0x00) means the length value is the data length only.
- EnterLengthBarrier / ExitLengthBarrier: reserve N bytes for a length,
  then fill in (bytes written since barrier) + addition, minus the
  barrier size itself when include_prefix is False.
"""
from __future__ import annotations

import struct

# Prefix flags
P_NONE = 0x00
P_INT8 = 0x01
P_INT16 = 0x02
P_INT32 = 0x04
P_LENGTH_ONLY = 0x00
P_WITH_PREFIX = 0x08


class Packet:
    """Growable big-endian byte buffer with a read cursor."""

    def __init__(self, data: bytes | bytearray | None = None, capacity: int = 256):
        if data is not None:
            self._buf = bytearray(data)
        else:
            self._buf = bytearray(capacity)
            del self._buf[:]  # start empty, grow on write
        self._off = 0
        self._barrier = -1

    # ---- writing ----
    def _ensure(self, n: int) -> None:
        need = self._off + n
        if need > len(self._buf):
            self._buf.extend(b"\x00" * (need - len(self._buf)))

    def write(self, data: bytes) -> None:
        self._ensure(len(data))
        self._buf[self._off:self._off + len(data)] = data
        self._off += len(data)

    def write_u8(self, v: int) -> None:
        self.write(struct.pack(">B", v & 0xFF))

    def write_u16(self, v: int) -> None:
        self.write(struct.pack(">H", v & 0xFFFF))

    def write_u32(self, v: int) -> None:
        self.write(struct.pack(">I", v & 0xFFFFFFFF))

    def write_u64(self, v: int) -> None:
        self.write(struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF))

    def write_i16(self, v: int) -> None:
        self.write(struct.pack(">h", v))

    def write_i32(self, v: int) -> None:
        self.write(struct.pack(">i", v))

    def write_i64(self, v: int) -> None:
        self.write(struct.pack(">q", v))

    def write_bytes_prefixed(self, data: bytes, flag: int) -> None:
        """Write length prefix then data. flag low 3 bits = prefix size."""
        size = flag & 0x07
        length = len(data)
        if flag & P_WITH_PREFIX:
            length += size
        if size == 1:
            self.write_u8(length)
        elif size == 2:
            self.write_u16(length)
        elif size == 4:
            self.write_u32(length)
        else:
            raise ValueError(f"bad prefix size {size}")
        self.write(data)

    def write_str(self, s: str, flag: int | None = None) -> None:
        b = s.encode("utf-8")
        if flag is None:
            self.write(b)
        else:
            self.write_bytes_prefixed(b, flag)

    def write_at_u16(self, v: int, offset: int) -> None:
        self._buf[offset:offset + 2] = struct.pack(">H", v & 0xFFFF)

    def enter_barrier(self, size: int) -> None:
        """Reserve `size` bytes for a length field."""
        self._barrier = self._off
        self._barrier_size = size
        self.write(b"\x00" * size)

    def exit_barrier(self, include_prefix: bool, addition: int = 0) -> None:
        assert self._barrier != -1, "no barrier set"
        written = self._off - self._barrier + addition
        if not include_prefix:
            written -= self._barrier_size
        size = self._barrier_size
        if size == 2:
            self._buf[self._barrier:self._barrier + 2] = struct.pack(">H", written & 0xFFFF)
        elif size == 4:
            self._buf[self._barrier:self._barrier + 4] = struct.pack(">I", written & 0xFFFFFFFF)
        else:
            raise ValueError(f"bad barrier size {size}")
        self._barrier = -1

    def skip(self, n: int) -> None:
        self._ensure(n)
        self._off += n

    def bytes(self) -> bytes:
        return bytes(self._buf[:self._off])

    # ---- reading ----
    def _read(self, n: int) -> bytes:
        if self._off + n > len(self._buf):
            raise EOFError(f"read {n} bytes at {self._off}, len {len(self._buf)}")
        b = bytes(self._buf[self._off:self._off + n])
        self._off += n
        return b

    def read_u8(self) -> int:
        return struct.unpack(">B", self._read(1))[0]

    def read_u16(self) -> int:
        return struct.unpack(">H", self._read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack(">I", self._read(4))[0]

    def read_u64(self) -> int:
        return struct.unpack(">Q", self._read(8))[0]

    def read_i16(self) -> int:
        return struct.unpack(">h", self._read(2))[0]

    def read_i32(self) -> int:
        return struct.unpack(">i", self._read(4))[0]

    def read_i64(self) -> int:
        return struct.unpack(">q", self._read(8))[0]

    def read_bytes(self, n: int) -> bytes:
        return self._read(n)

    def read_bytes_prefixed(self, flag: int) -> bytes:
        size = flag & 0x07
        if size == 1:
            length = self.read_u8()
        elif size == 2:
            length = self.read_u16()
        elif size == 4:
            length = self.read_u32()
        else:
            raise ValueError(f"bad prefix size {size}")
        if flag & P_WITH_PREFIX:
            length -= size
        return self._read(length)

    def read_str_prefixed(self, flag: int) -> str:
        return self.read_bytes_prefixed(flag).decode("utf-8", "replace")

    def read_rest(self) -> bytes:
        return self._read(len(self._buf) - self._off)

    def remaining(self) -> int:
        return len(self._buf) - self._off

    def tell(self) -> int:
        return self._off

    def seek(self, off: int) -> None:
        self._off = off
