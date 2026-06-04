from __future__ import annotations
from typing import List, Optional, Tuple, Iterable


def _to_int32(x: int) -> int:
    x = x & 0xFFFFFFFF
    if x >= 0x80000000:
        x -= 0x100000000
    return x


def _java_hash(s: str) -> int:
    h = 0
    for c in s:
        h = _to_int32(31 * h + ord(c))
    return h


def _improve(hcode: int) -> int:
    h = _to_int32(hcode + _to_int32(~_to_int32(hcode << 9)))
    h = _to_int32(h ^ ((h & 0xFFFFFFFF) >> 14))
    h = _to_int32(h + _to_int32(h << 4))
    h = _to_int32(h ^ ((h & 0xFFFFFFFF) >> 10))
    return h


def scala_set_key(v) -> tuple:
    """Sort key replicating Scala mutable.HashTable improve (used in assign_layers)."""
    h = _improve(_java_hash(str(v))) & 0xFFFFFFFF
    chunks = []
    for _ in range(7):
        chunks.append(h & 0x1F)
        h >>= 5
    return tuple(chunks)


def _improve_murmur3(hcode: int) -> int:
    """Scala immutable.HashSet improve (MurmurHash3 avalanche)."""
    h = hcode & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h


def scala_immutable_set_key(v) -> tuple:
    """Sort key replicating Scala immutable.HashSet iteration order (MurmurHash3)."""
    h = _improve_murmur3(_java_hash(str(v)) & 0xFFFFFFFF)
    chunks = []
    for _ in range(7):
        chunks.append(h & 0x1F)
        h >>= 5
    return tuple(chunks)


def transform_values(d: dict, f) -> dict:
    return {k: f(v) for k, v in d.items()}


def with_previous(iterable: Iterable) -> List[Tuple[Optional, object]]:
    items = list(iterable)
    if not items:
        return []
    previous = [None] + items[:-1]
    return list(zip(previous, items))


def with_previous_and_next(iterable: Iterable) -> List[Tuple]:
    items = list(iterable)
    if not items:
        return []
    previous = [None] + items[:-1]
    nxt = items[1:] + [None]
    return list(zip(previous, items, nxt))


def adjacent_pairs(xs: List) -> List[Tuple]:
    return list(zip(xs, xs[1:]))


def adjacent_triples(xs: List) -> List[Tuple]:
    return [(xs[i], xs[i+1], xs[i+2]) for i in range(len(xs)-2)]


def adjacent_pairs_with_previous_and_next(xs: List) -> List[Tuple]:
    result = []
    for i in range(len(xs) - 1):
        prev = xs[i-1] if i > 0 else None
        a = xs[i]
        b = xs[i+1]
        nxt = xs[i+2] if i+2 < len(xs) else None
        result.append((prev, a, b, nxt))
    return result


def iterate(t, f):
    while True:
        result = f(t)
        if result is None:
            return t
        t = result


def multiset_compare(set1: List, set2: List) -> bool:
    return mk_multiset(set1) == mk_multiset(set2)


def mk_multiset(lst: List) -> dict:
    result = {}
    for item in lst:
        result[item] = result.get(item, 0) + 1
    return result


def remove_first(xs: List, x) -> List:
    result = list(xs)
    try:
        idx = result.index(x)
        result.pop(idx)
    except ValueError:
        pass
    return result


def make_map(s: Iterable, f) -> dict:
    return {t: f(t) for t in s}


def signum(x: int) -> int:
    if x < 0:
        return -1
    elif x == 0:
        return 0
    else:
        return 1


def conditionally_map(xs: List, fn) -> List:
    result = []
    for x in xs:
        try:
            r = fn(x)
            result.append(r)
        except Exception:
            result.append(x)
    return result


def add_to_multimap(m: dict, k, v) -> dict:
    new_m = dict(m)
    new_m[k] = [v] + new_m.get(k, [])
    return new_m
