#!/usr/bin/env python3
"""Render ANSI-colored terminal text to a PNG that looks like a real terminal
window. Used to generate README screenshots from the tool's actual output
(not mockups) so the images stay truthful if the tool changes."""

import re
import sys
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

# 256-color-ish approximations for the codes pcap_analyzer.py actually emits
ANSI_FG = {
    "30": "#5c6370", "31": "#e06c75", "32": "#98c379", "33": "#e5c07b",
    "34": "#61afef", "35": "#c678dd", "36": "#56b6c2", "37": "#d0d0d0",
}
RESET = "\033[0m"
CODE_RE = re.compile(r"\033\[([0-9;]*)m")

BG = "#0d1117"
TITLEBAR = "#161b22"
DEFAULT_FG = "#c9d1d9"
DIM_FG = "#6e7681"


def strip_and_tokenize(line):
    """Split a line into (text, color, bold, dim) runs based on ANSI codes."""
    runs = []
    pos = 0
    color, bold, dim = DEFAULT_FG, False, False
    for m in CODE_RE.finditer(line):
        if m.start() > pos:
            runs.append((line[pos:m.start()], color, bold, dim))
        codes = m.group(1).split(";") if m.group(1) else ["0"]
        for c in codes:
            if c == "0" or c == "":
                color, bold, dim = DEFAULT_FG, False, False
            elif c == "1":
                bold = True
            elif c == "2":
                dim = True
            elif c in ANSI_FG:
                color = ANSI_FG[c]
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], color, bold, dim))
    return runs or [("", color, bold, dim)]


def render(lines, out_path, font_size=15, pad=22, max_width_chars=118,
          title="claude@soc-lab: ~/pcap-analyzer"):
    font = ImageFont.truetype(FONT_PATH, font_size)
    font_b = ImageFont.truetype(FONT_BOLD, font_size)

    bbox = font.getbbox("M")
    ch_w = bbox[2] - bbox[0] + 1
    line_h = int(font_size * 1.55)

    clean_lines = [ln.replace("\t", "    ") for ln in lines]
    content_w = max((len(CODE_RE.sub("", ln)) for ln in clean_lines), default=80)
    content_w = min(content_w, max_width_chars)

    titlebar_h = 40
    img_w = pad * 2 + content_w * ch_w
    img_h = titlebar_h + pad * 2 + len(clean_lines) * line_h

    img = Image.new("RGB", (img_w, img_h), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, img_w, titlebar_h], fill=TITLEBAR)
    for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
        draw.ellipse([18 + i * 22, titlebar_h // 2 - 6, 18 + i * 22 + 12,
                      titlebar_h // 2 + 6], fill=c)
    draw.text((img_w // 2, titlebar_h // 2), title, fill="#8b949e",
              font=font, anchor="mm")

    y = titlebar_h + pad
    for line in clean_lines:
        x = pad
        for text, color, bold, dim in strip_and_tokenize(line):
            if not text:
                continue
            fg = DIM_FG if dim else color
            f = font_b if bold else font
            draw.text((x, y), text, fill=fg, font=f)
            x += len(text) * ch_w
        y += line_h

    img.save(out_path)
    print(f"[+] {out_path}  ({img_w}x{img_h})")


if __name__ == "__main__":
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    end = int(sys.argv[3]) if len(sys.argv) > 3 else None
    title = sys.argv[4] if len(sys.argv) > 4 else "claude@soc-lab: ~/pcap-analyzer"
    with open(sys.argv[1], "r") as fh:
        all_lines = fh.read().splitlines()
    chunk = all_lines[start:end]
    render(chunk, sys.argv[5] if len(sys.argv) > 5 else "out.png", title=title)
