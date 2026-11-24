"""Minimal protobuf encode/decode (varint + length-delimited only),
enough for the QQ login messages we need.

Field spec: (field_number, wire_type, value) where wire_type 0 = varint,
2 = length-delimited. Values are int (varint), bytes/str (len-delim),
or a dict {field_number: value} for embedded messages.
"""
from __future__ import annotations


def encode_varint(value: int) -> bytes:
    out = bytearray()
    value &= (1 << 64) - 1
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def decode_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def encode_field(num: int, wire: int, value) -> bytes:
    key = encode_varint((num << 3) | wire)
    if wire == 0:
        return key + encode_varint(value)
    if wire == 2:
        if isinstance(value, str):
            value = value.encode("utf-8")
        if isinstance(value, dict):
            value = encode_message(value)
        return key + encode_varint(len(value)) + value
    raise ValueError(f"unsupported wire type {wire}")


def encode_message(fields: dict[int, object]) -> bytes:
    """fields: {field_number: value}. value int -> varint, bytes/str/dict -> len-delim."""
    out = bytearray()
    for num in sorted(fields):
        value = fields[num]
        if value is None:
            continue
        if isinstance(value, bool):
            out += encode_field(num, 0, int(value))
        elif isinstance(value, int):
            out += encode_field(num, 0, value)
        elif isinstance(value, (bytes, str, dict)):
            out += encode_field(num, 2, value)
        else:
            raise ValueError(f"unsupported value type {type(value)} for field {num}")
    return bytes(out)


def decode_message(buf: bytes) -> dict[int, object]:
    """Decode to {field_number: value}; repeated fields become lists.
    varint -> int, len-delim -> bytes (caller interprets)."""
    out: dict[int, object] = {}
    pos = 0
    while pos < len(buf):
        key, pos = decode_varint(buf, pos)
        num, wire = key >> 3, key & 0x07
        if wire == 0:
            value, pos = decode_varint(buf, pos)
        elif wire == 2:
            ln, pos = decode_varint(buf, pos)
            value = buf[pos:pos + ln]
            pos += ln
        elif wire == 5:
            value = buf[pos:pos + 4]
            pos += 4
        elif wire == 1:
            value = buf[pos:pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wire} at field {num}")
        if num in out:
            prev = out[num]
            out[num] = prev + [value] if isinstance(prev, list) else [prev, value]
        else:
            out[num] = value
    return out


def get_str(fields: dict, num: int, default: str = "") -> str:
    v = fields.get(num)
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return default


def get_bytes(fields: dict, num: int, default: bytes = b"") -> bytes:
    v = fields.get(num)
    return v if isinstance(v, bytes) else default


def get_int(fields: dict, num: int, default: int = 0) -> int:
    v = fields.get(num)
    return v if isinstance(v, int) else default


def get_msg(fields: dict, num: int) -> dict:
    v = fields.get(num)
    if isinstance(v, bytes):
        return decode_message(v)
    return {}
