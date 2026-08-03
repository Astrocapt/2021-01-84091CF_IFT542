#!/usr/bin/env python3
"""
scripts/make_dfd.py
===================
Generates the Level-1 data-flow diagram with trust boundaries (Task 1).

Written as a generator rather than a hand-drawn image so the diagram can be
regenerated whenever the architecture changes. Outputs docs/dfd.svg and
docs/dfd.png.

Conventions:
  squares = external entities   circles = processes   open bars = data stores
  dashed red = trust boundary   solid arrows = data flows
  dotted arrows = audit/logging flows
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

W, H = 1320, 1010

INK, ACCENT, STORE, EXT = "#1b2430", "#1f4e79", "#7a4a2b", "#4a5a6a"
BOUND, FLOW, LOGFLOW = "#b3312c", "#33455a", "#9a8b72"

P_CX, P_R = 470, 56
S_X, S_W, S_H = 872, 248, 58
GUTTER = 826
LOGBUS = 600

parts: list[str] = []
add = parts.append

add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
    f'viewBox="0 0 {W} {H}" font-family="Georgia, serif">')
add(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
add('<defs>'
    f'<marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
    f'markerHeight="7" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{FLOW}"/></marker>'
    f'<marker id="al" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
    f'markerHeight="7" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{LOGFLOW}"/></marker>'
    '</defs>')

add(f'<text x="{W//2}" y="34" text-anchor="middle" font-size="21" '
    f'font-weight="bold" fill="{INK}">Student Registration Web Application '
    f'&#8212; Level 1 Data-Flow Diagram</text>')
add(f'<text x="{W//2}" y="56" text-anchor="middle" font-size="13" fill="{EXT}">'
    f'IFT 542 Practical Assignment &#183; dashed red lines are trust boundaries</text>')


def boundary(x, y, w, h, label):
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" '
        f'stroke="{BOUND}" stroke-width="1.8" stroke-dasharray="9 6" rx="8"/>')
    add(f'<text x="{x + 10}" y="{y - 8}" font-size="12.5" font-weight="bold" '
        f'fill="{BOUND}">{label}</text>')


def label_block(cx, top, h, ident, lines, colour):
    total = 15 + len(lines) * 13
    start = top + (h - total) / 2 + 12
    add(f'<text x="{cx}" y="{start}" text-anchor="middle" font-size="12.5" '
        f'font-weight="bold" fill="{colour}">{ident}</text>')
    for i, line in enumerate(lines):
        add(f'<text x="{cx}" y="{start + 16 + i * 13}" text-anchor="middle" '
            f'font-size="11.5" fill="{INK}">{line}</text>')


def entity(x, cy, w, h, ident, lines):
    add(f'<rect x="{x}" y="{cy - h/2}" width="{w}" height="{h}" fill="#eef2f6" '
        f'stroke="{EXT}" stroke-width="1.6" rx="3"/>')
    label_block(x + w / 2, cy - h / 2, h, ident, lines, EXT)


def process(cy, ident, lines, cx=P_CX, r=P_R):
    add(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="#eaf0f6" stroke="{ACCENT}" '
        f'stroke-width="1.8"/>')
    label_block(cx, cy - r, 2 * r, ident, lines, ACCENT)


def store(cy, ident, lines):
    y = cy - S_H / 2
    add(f'<rect x="{S_X}" y="{y}" width="{S_W}" height="{S_H}" fill="#f7f1ea" '
        f'stroke="{STORE}" stroke-width="1.4"/>')
    add(f'<line x1="{S_X}" y1="{y}" x2="{S_X+S_W}" y2="{y}" stroke="{STORE}" stroke-width="2.6"/>')
    add(f'<line x1="{S_X}" y1="{y+S_H}" x2="{S_X+S_W}" y2="{y+S_H}" stroke="{STORE}" stroke-width="2.6"/>')
    label_block(S_X + S_W / 2, y, S_H, ident, lines, STORE)


def path(points, label=None, lx=None, ly=None, anchor="middle",
         dotted=False, back=False):
    d = " ".join(f"{'M' if i == 0 else 'L'} {x} {y}" for i, (x, y) in enumerate(points))
    colour = LOGFLOW if dotted else FLOW
    marker = "al" if dotted else "a"
    dash = ' stroke-dasharray="3 4"' if dotted else (
        ' stroke-dasharray="7 5"' if back else "")
    add(f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="1.5" '
        f'marker-end="url(#{marker})"{dash}/>')
    if label:
        add(f'<text x="{lx}" y="{ly}" text-anchor="{anchor}" font-size="11" '
            f'fill="{colour}">{label}</text>')


# --- trust boundaries ------------------------------------------------------
boundary(30, 120, 250, 540, "TB1 &#8212; Untrusted client zone")
boundary(340, 96, 480, 880, "TB2 &#8212; Application trust boundary (localhost host)")
boundary(852, 110, 288, 720, "TB3 &#8212; Data-store trust boundary")
boundary(852, 880, 288, 96, "TB4 &#8212; External network boundary")

# --- external entities -----------------------------------------------------
entity(56, 190, 196, 72, "E1 Administrator", ["Manages courses", "and enrolments"])
entity(56, 380, 196, 72, "E2 Student", ["Profile, registration,", "document upload"])
entity(56, 570, 196, 72, "E3 Anonymous visitor", ["Reaches the", "sign-in page only"])
entity(866, 928, 260, 66, "E4 Registry service", ["Allowlisted external", "document host"])

# --- processes and stores, aligned in rows ---------------------------------
process(170, "P1", ["Authenticate", "and session"])
process(290, "P2", ["Manage", "profile"])
process(410, "P3", ["Course", "registration"])
process(530, "P4", ["Document", "upload"])
process(650, "P5", ["URL preview", "and import"])
process(770, "P6", ["Administrative", "management"])
process(898, "P7", ["Security", "logging"], cx=700, r=50)

store(170, "D1 users", ["credentials, role, lockout state"])
store(290, "D2 profiles", ["student-editable detail"])
store(410, "D3 courses / enrolments", ["catalogue and registrations"])
store(530, "D4 documents", ["upload metadata and files"])
store(650, "D5 login_attempts", ["rate-limiting counters"])
store(770, "D6 audit_log", ["append-only security events"])

# --- client zone -> application (crossing TB1 and TB2) ---------------------
CH = 300
LEFT = P_CX - P_R - 2

path([(252, 176), (CH, 176), (CH, 152), (LEFT, 152)],
     "admin credentials + OTP", 296, 140, anchor="start")
path([(252, 204), (CH, 204), (CH, 762), (LEFT, 762)],
     "course and enrolment changes", 306, 754, anchor="start")

path([(252, 366), (CH + 16, 366), (CH + 16, 180), (LEFT, 180)],
     "credentials", 322, 214, anchor="start")
path([(252, 378), (CH + 30, 378), (CH + 30, 290), (LEFT, 290)],
     "profile edits + CSRF token", 336, 282, anchor="start")
path([(252, 390), (CH + 44, 390), (CH + 44, 412), (LEFT, 412)],
     "course selection", 350, 430, anchor="start")
path([(252, 402), (CH + 58, 402), (CH + 58, 532), (LEFT, 532)],
     "document file", 364, 524, anchor="start")
path([(252, 414), (CH + 72, 414), (CH + 72, 652), (LEFT, 652)],
     "document URL", 378, 644, anchor="start")

path([(252, 558), (CH, 558), (CH, 196), (LEFT, 196)],
     "sign-in attempt", 258, 552, anchor="start")

path([(LEFT, 140), (CH - 18, 140), (CH - 18, 354), (252, 354)],
     "session cookie; generic errors only", 258, 342, anchor="start", back=True)

# --- application -> data stores (crossing TB3) -----------------------------
RIGHT = P_CX + P_R + 2
path([(RIGHT, 170), (S_X - 2, 170)], "lookup by e-mail; verify hash", 706, 160)
path([(RIGHT, 290), (S_X - 2, 290)], "read / write profile", 706, 280)
path([(RIGHT, 410), (S_X - 2, 410)], "enrol / drop", 706, 400)
path([(RIGHT, 530), (S_X - 2, 530)], "store metadata", 706, 520)

path([(P_CX + 40, 208), (GUTTER, 208), (GUTTER, 640), (S_X - 2, 640)],
     "record attempt", 832, 618, anchor="start")
path([(P_CX + 40, 732), (GUTTER - 20, 732), (GUTTER - 20, 428), (S_X - 2, 428)],
     "catalogue writes", 706, 446)

# --- audit flows (dotted) --------------------------------------------------
for cy in (170, 290, 410, 530, 650, 770):
    path([(P_CX + 24, cy + 50), (LOGBUS, cy + 50), (LOGBUS, 884)], None, dotted=True)
add(f'<text x="{LOGBUS + 10}" y="852" font-size="11" fill="{LOGFLOW}">'
    f'security events from P1&#8211;P6</text>')
path([(752, 878), (S_X - 2, 796)], "append event", 806, 832, dotted=True)

# --- application -> external service (crossing TB4) ------------------------
path([(RIGHT, 668), (790, 668), (790, 946), (864, 946)],
     "vetted outbound fetch", 796, 966, anchor="start")
path([(864, 908), (772, 908), (772, 684), (RIGHT, 684)],
     "preview metadata only", 796, 900, anchor="start", back=True)

# --- legend ----------------------------------------------------------------
lx, ly = 40, 690
add(f'<rect x="{lx}" y="{ly}" width="256" height="152" fill="#fbfcfd" '
    f'stroke="#d8dee6" rx="5"/>')
add(f'<text x="{lx+14}" y="{ly+24}" font-size="13" font-weight="bold" fill="{INK}">Legend</text>')
add(f'<rect x="{lx+16}" y="{ly+36}" width="28" height="17" fill="#eef2f6" stroke="{EXT}"/>')
add(f'<text x="{lx+56}" y="{ly+49}" font-size="11.5" fill="{INK}">External entity</text>')
add(f'<circle cx="{lx+30}" cy="{ly+74}" r="10" fill="#eaf0f6" stroke="{ACCENT}"/>')
add(f'<text x="{lx+56}" y="{ly+78}" font-size="11.5" fill="{INK}">Process</text>')
add(f'<line x1="{lx+16}" y1="{ly+94}" x2="{lx+44}" y2="{ly+94}" stroke="{STORE}" stroke-width="2.6"/>')
add(f'<line x1="{lx+16}" y1="{ly+106}" x2="{lx+44}" y2="{ly+106}" stroke="{STORE}" stroke-width="2.6"/>')
add(f'<text x="{lx+56}" y="{ly+104}" font-size="11.5" fill="{INK}">Data store</text>')
add(f'<line x1="{lx+16}" y1="{ly+122}" x2="{lx+44}" y2="{ly+122}" stroke="{FLOW}" stroke-width="1.5"/>')
add(f'<text x="{lx+56}" y="{ly+126}" font-size="11.5" fill="{INK}">Data flow</text>')
add(f'<line x1="{lx+16}" y1="{ly+138}" x2="{lx+44}" y2="{ly+138}" stroke="{LOGFLOW}" '
    f'stroke-width="1.5" stroke-dasharray="3 4"/>')
add(f'<text x="{lx+56}" y="{ly+142}" font-size="11.5" fill="{INK}">Audit flow</text>')

add('</svg>')

svg = "\n".join(parts)
DOCS.mkdir(parents=True, exist_ok=True)
(DOCS / "dfd.svg").write_text(svg, encoding="utf-8")

try:
    import cairosvg
    cairosvg.svg2png(bytestring=svg.encode("utf-8"),
                     write_to=str(DOCS / "dfd.png"),
                     output_width=W * 2, output_height=H * 2)
    print("Wrote docs/dfd.svg and docs/dfd.png")
except ImportError:
    print("Wrote docs/dfd.svg (install cairosvg for the PNG)")
