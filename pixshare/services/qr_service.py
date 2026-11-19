"""Petit générateur de QR codes (mode octets, correction M, versions 1 à 6 : jusqu'à 106 caractères).

Écrit ici pour ne dépendre d'aucune bibliothèque de plus. Sortie en SVG (net à l'impression) ou PNG.
"""
from __future__ import annotations

import io

# Versions 1 à 6, niveau M : (codes de données par bloc, nombre de blocs, codes de correction par bloc)
_BLOCKS = {1: (16, 1, 10), 2: (28, 1, 16), 3: (44, 1, 26), 4: (32, 2, 18), 5: (43, 2, 24), 6: (27, 4, 16)}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34]}
MAX_BYTES = 106

# Corps de Galois GF(256), polynôme 0x11D
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_ecc(data: list[int], n: int) -> list[int]:
    gen = [1]
    for i in range(n):  # (x - α^i)
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= _gmul(c, _EXP[i])
        gen = nxt
    rem = list(data) + [0] * n
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gmul(gen[j], coef)
    return rem[len(data):]


def _codewords(text: bytes) -> tuple[int, list[int]]:
    for version in range(1, 7):
        per_block, blocks, _ec = _BLOCKS[version]
        if len(text) <= per_block * blocks - 2:
            break
    else:
        raise ValueError("Texte trop long pour le QR code")
    capacity = per_block * blocks
    bits = [0, 1, 0, 0] + [int(b) for b in f"{len(text):08b}"]
    for byte in text:
        bits += [int(b) for b in f"{byte:08b}"]
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < capacity:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    per_block, blocks, ec = _BLOCKS[version]
    chunks = [data[i * per_block:(i + 1) * per_block] for i in range(blocks)]
    eccs = [_rs_ecc(c, ec) for c in chunks]
    out = [c[i] for i in range(per_block) for c in chunks] + [e[i] for i in range(ec) for e in eccs]
    return version, out


def _format_bits(mask: int) -> int:
    data = (0 << 3) | mask  # niveau M = 00
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


_MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def _build(version: int, words: list[int], mask: int) -> list[list[bool]]:
    size = 17 + 4 * version
    m = [[False] * size for _ in range(size)]
    fn = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        m[y][x] = dark
        fn[y][x] = True

    for i in range(size):  # lignes de synchronisation
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):  # repères des coins (+ séparateurs)
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    d = max(abs(dx), abs(dy))
                    put(x, y, d not in (2, 4))
    pos = _ALIGN[version]
    for i, ax in enumerate(pos):  # motifs d'alignement
        for j, ay in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
    fmt = _format_bits(mask)
    bit = lambda i: (fmt >> i) & 1 == 1  # noqa: E731
    for i in range(6):
        put(8, i, bit(i))
    put(8, 7, bit(6))
    put(8, 8, bit(7))
    put(7, 8, bit(8))
    for i in range(9, 15):
        put(14 - i, 8, bit(i))
    for i in range(8):
        put(size - 1 - i, 8, bit(i))
    for i in range(8, 15):
        put(8, size - 15 + i, bit(i))
    put(8, size - 8, True)  # module toujours sombre

    total = len(words) * 8
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not fn[y][x]:
                    dark = i < total and (words[i >> 3] >> (7 - (i & 7))) & 1 == 1
                    i += 1
                    m[y][x] = dark != _MASKS[mask](x, y)
        right -= 2
    return m


def _penalty(m: list[list[bool]]) -> int:
    size, score = len(m), 0
    for rows in (m, list(map(list, zip(*m)))):
        for row in rows:
            run, prev = 0, None
            for v in row:
                run = run + 1 if v == prev else 1
                prev = v
                if run == 5:
                    score += 3
                elif run > 5:
                    score += 1
    for y in range(size - 1):
        for x in range(size - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, m))
    score += abs(dark * 20 - size * size * 10) // (size * size) * 10
    return score


def matrix(text: str) -> list[list[bool]]:
    data = text.encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("Texte trop long pour le QR code")
    version, words = _codewords(data)
    return min((_build(version, words, k) for k in range(8)), key=_penalty)


def svg(text: str, scale: int = 8, border: int = 4) -> str:
    m = matrix(text)
    n = len(m) + 2 * border
    path = "".join(f"M{x + border},{y + border}h1v1h-1z" for y, row in enumerate(m) for x, v in enumerate(row) if v)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * scale}" height="{n * scale}" '
            f'shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></svg>')


def png(text: str, scale: int = 10, border: int = 4) -> bytes:
    from PIL import Image
    m = matrix(text)
    n = len(m) + 2 * border
    img = Image.new("1", (n, n), 1)
    px = img.load()
    for y, row in enumerate(m):
        for x, v in enumerate(row):
            if v:
                px[x + border, y + border] = 0
    img = img.resize((n * scale, n * scale), Image.NEAREST)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
