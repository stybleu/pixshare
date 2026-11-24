"""Rapport d'intervention en PDF A4 (dessiné avec Pillow : aucune dépendance en plus).

Page 1 : en-tête, machine, lieu, n° d'intervention, date et heure (Paris), technicien, commentaire,
puis les photos « Avant », « Après » et « Autres » par 2, avec leur légende ; pages suivantes si besoin.
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from PIL import Image, ImageDraw, ImageFont

DPI = 150
W, H = 1240, 1754                 # A4 à 150 dpi
MARGIN = 80
INK, MUTED, LINE, ACCENT = (25, 30, 45), (95, 105, 125), (215, 220, 230), (79, 70, 229)
LABELS = {"avant": "Avant", "apres": "Après", "autre": "Autres photos"}


_FONTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "fonts")


def _font(size: int, bold: bool = False):
    """DejaVu Sans jointe au site (accents français compris) ; police de secours sinon."""
    try:
        return ImageFont.truetype(os.path.join(_FONTS, "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"), size)
    except OSError:
        try:
            return ImageFont.load_default(size=size)
        except TypeError:
            return ImageFont.load_default()


def _paris(iso: str) -> str:
    try:
        d = datetime.fromisoformat(iso).astimezone(ZoneInfo("Europe/Paris"))
        return d.strftime("%d/%m/%Y à %H:%M")
    except (ValueError, TypeError):
        return iso or "—"


def _wrap(draw, text: str, font, width: int) -> list[str]:
    lines = []
    for para in (text or "").splitlines() or [""]:
        words, line = para.split(), ""
        for word in words:
            test = (line + " " + word).strip()
            if draw.textlength(test, font=font) <= width:
                line = test
            else:
                if line:
                    lines.append(line)
                line = word
        lines.append(line)
    return lines


class _Pages:
    def __init__(self, title: str, brand: str):
        self.pages, self.title, self.brand = [], title, brand
        self.new()

    def new(self):
        self.page = Image.new("RGB", (W, H), "white")
        self.d = ImageDraw.Draw(self.page)
        self.pages.append(self.page)
        self.d.rectangle([0, 0, W, 14], fill=ACCENT)
        self.d.text((MARGIN, 40), self.brand, font=_font(22, True), fill=ACCENT)
        self.d.text((W - MARGIN, 40), self.title, font=_font(22), fill=MUTED, anchor="ra")
        self.d.line([MARGIN, 82, W - MARGIN, 82], fill=LINE, width=2)
        self.y = 110

    def need(self, height: int):
        if self.y + height > H - 110:
            self.new()

    def finish(self, footer: str) -> bytes:
        total = len(self.pages)
        for n, page in enumerate(self.pages, 1):
            d = ImageDraw.Draw(page)
            d.line([MARGIN, H - 80, W - MARGIN, H - 80], fill=LINE, width=2)
            d.text((MARGIN, H - 62), footer, font=_font(18), fill=MUTED)
            d.text((W - MARGIN, H - 62), f"Page {n} / {total}", font=_font(18), fill=MUTED, anchor="ra")
        out = io.BytesIO()
        self.pages[0].save(out, "PDF", save_all=True, append_images=self.pages[1:], resolution=DPI)
        return out.getvalue()


def build(item: dict, photo_loader, brand: str = "Rapport de maintenance") -> bytes:
    """`photo_loader(photo_id) -> bytes JPEG` (déchiffré)."""
    machine = item.get("machine") or {}
    p = _Pages("Rapport d'intervention", brand)
    d = p.d
    d.text((MARGIN, p.y), machine.get("name") or "Machine", font=_font(46, True), fill=INK)
    p.y += 70
    rows = [("Lieu", machine.get("location") or "—"),
            ("N° d'intervention", item.get("ref") or "—"),
            ("Date", _paris(item.get("created_at", ""))),
            ("Technicien", item.get("author") or "—"),
            ("Photos", str(len(item.get("photos") or [])))]
    for label, value in rows:
        d.text((MARGIN, p.y), label, font=_font(24), fill=MUTED)
        d.text((MARGIN + 300, p.y), str(value), font=_font(24), fill=INK)
        p.y += 40
    p.y += 16
    if item.get("comment"):
        d.text((MARGIN, p.y), "Commentaire", font=_font(28, True), fill=INK)
        p.y += 46
        for line in _wrap(d, item["comment"], _font(24), W - 2 * MARGIN):
            p.need(36)
            p.d.text((MARGIN, p.y), line, font=_font(24), fill=INK)
            p.y += 36
        p.y += 20

    col_w = (W - 2 * MARGIN - 30) // 2
    for kind in ("avant", "apres", "autre"):
        photos = [ph for ph in item.get("photos") or [] if ph.get("kind") == kind]
        if not photos:
            continue
        p.need(120)
        p.d.text((MARGIN, p.y), f"{LABELS[kind]} ({len(photos)})", font=_font(30, True), fill=INK)
        p.y += 52
        for i in range(0, len(photos), 2):
            pair, tiles = photos[i:i + 2], []
            for ph in pair:
                try:
                    with Image.open(io.BytesIO(photo_loader(ph["id"]))) as img:
                        img = img.convert("RGB")
                        img.thumbnail((col_w, 640), Image.LANCZOS)
                        tiles.append((img.copy(), ph))
                except Exception:
                    tiles.append((None, ph))
            row_h = max((t[0].height if t[0] else 120) for t in tiles) + 50
            p.need(row_h)
            for col, (img, ph) in enumerate(tiles):
                x = MARGIN + col * (col_w + 30)
                if img is not None:
                    p.page.paste(img, (x, p.y))
                    p.d.rectangle([x, p.y, x + img.width - 1, p.y + img.height - 1], outline=LINE, width=2)
                    cap_y = p.y + img.height + 10
                else:
                    p.d.rectangle([x, p.y, x + col_w, p.y + 120], outline=LINE, width=2)
                    p.d.text((x + 20, p.y + 45), "Photo illisible", font=_font(22), fill=MUTED)
                    cap_y = p.y + 130
                p.d.text((x, cap_y), (ph.get("name") or "")[:60], font=_font(18), fill=MUTED)
            p.y += row_h + 10
    return p.finish(f"Généré le {datetime.now(ZoneInfo('Europe/Paris')).strftime('%d/%m/%Y à %H:%M')} · document confidentiel")
