"""Reproduce Scala 2.11 hashing + immutable collection iteration order.

Used to replicate the iteration order of `Map[EdgeInfo, _]` / `Set` that the
Scala layout code relies on for deterministic output.

- String.hashCode: Java 31*h+c, 32-bit overflow.
- MurmurHash3.productHash: case class hashCode (ScalaRunTime._hashCode).
- improve: immutable.HashMap/HashSet hash spread (Scala 2.11).
- HAMT order: iteration order of immutable HashMap/HashSet (>=5 elems).
"""
from __future__ import annotations

MASK = 0xFFFFFFFF

PRODUCT_SEED = 0xCAFEBABE


def _i32(x: int) -> int:
    x &= MASK
    if x >= 0x80000000:
        x -= 0x100000000
    return x


def java_string_hash(s: str) -> int:
    h = 0
    for c in s:
        h = _i32(31 * h + ord(c))
    return h


# --- MurmurHash3 (scala.util.hashing.MurmurHash3) ---

def _rotl(x: int, n: int) -> int:
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK


def _mix_last(h: int, data: int) -> int:
    k = data & MASK
    k = (k * 0xCC9E2D51) & MASK
    k = _rotl(k, 15)
    k = (k * 0x1B873593) & MASK
    return (h ^ k) & MASK


def _mix(h: int, data: int) -> int:
    h = _mix_last(h, data)
    h = _rotl(h, 13)
    return ((h * 5) + 0xE6546B64) & MASK


def _avalanche(h: int) -> int:
    h &= MASK
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & MASK
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & MASK
    h ^= h >> 16
    return h & MASK


def _finalize(h: int, length: int) -> int:
    return _avalanche((h ^ length) & MASK)


def product_hash(element_hashes, seed: int = PRODUCT_SEED) -> int:
    """MurmurHash3.productHash given the `.##` of each product element."""
    elems = list(element_hashes)
    arr = len(elems)
    if arr == 0:
        return 0
    h = seed & MASK
    for eh in elems:
        h = _mix(h, eh & MASK)
    return _i32(_finalize(h, arr))


def bool_hash(b: bool) -> int:
    return 1231 if b else 1237


def point_hash(row: int, column: int) -> int:
    # Point(row, column) is a case class; Int.## == the int value.
    return product_hash([row & MASK, column & MASK])


# --- improve (immutable.HashMap / HashSet hash spread, Scala 2.11) ---

def improve(hcode: int) -> int:
    h = _i32(hcode + _i32(~_i32(hcode << 9)))
    h = _i32(h ^ ((h & MASK) >> 14))
    h = _i32(h + _i32(h << 4))
    h = _i32(h ^ ((h & MASK) >> 10))
    return h


def hamt_key(hcode: int) -> tuple:
    """Sort key giving immutable HashMap/HashSet iteration order.

    The trie indexes by 5-bit groups of improve(hash), least-significant first.
    foreach visits index 0..31 at each level, recursing -> lexicographic order
    of the 5-bit groups read LSB-first.
    """
    h = improve(hcode) & MASK
    chunks = []
    for _ in range(7):
        chunks.append(h & 0x1F)
        h >>= 5
    return tuple(chunks)
