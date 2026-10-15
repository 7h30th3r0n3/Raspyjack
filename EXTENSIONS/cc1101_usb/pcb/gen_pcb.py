#!/usr/bin/env python3
"""
Gerber generator for the RaspyJack CC1101-over-USB *carrier* PCB.

A 2-layer board that receives an ESP32-C3 SuperMini (2x8, 0.6"/15.24mm rows)
and a generic 1x8 CC1101 module, wired per EXTENSIONS/cc1101_usb (C3 pin map:
SCK=4, MISO=5, MOSI=6, CS=7, GDO0=10, GDO2=3).

No EDA tool is used: this emits RS-274X Gerbers + Excellon drill directly, runs
a geometric design-rule check (copper clearance, hole spacing), and writes an
SVG preview. Upload the gerbers/ folder (zipped) to JLCPCB/PCBWay.

    python3 gen_pcb.py            # writes gerbers/ and preview.svg

Dimensions in mm. Origin bottom-left. Board 40 x 26 mm, 2 layers, 1.6mm.
"""
import os
import math

# ----------------------------------------------------------------------------
# Board parameters
# ----------------------------------------------------------------------------
BOARD_W = 44.0
BOARD_H = 26.0

TRACE_SIG = 0.30
TRACE_PWR = 0.45
CLEAR = 0.20                 # min copper clearance (DRC)

PAD_OD = 1.60                # header through-hole pad outer diameter
PAD_DRILL = 1.02             # header drill (fits 2.54mm pins)
VIA_OD = 0.90
VIA_DRILL = 0.45
MH_DRILL = 2.20              # M2 mounting hole (NPTH)
MASK_EXPAND = 0.05           # soldermask opening = pad + 2*expand

PITCH = 2.54
ROW = 15.24                  # C3 SuperMini row-to-row (0.6")

# Pin Y positions (8 rows), index 0 = bottom
Y0 = 4.11
PY = [Y0 + i * PITCH for i in range(8)]   # 4.11 .. 21.89

X_C3L = 6.00
X_C3R = X_C3L + ROW                       # 21.24
# CC1101 2x4 (nRF24 footprint, 2.54mm): left col faces C3, right col faces edge
X_CCL = 32.00
X_CCR = X_CCL + PITCH                      # 34.54

# ----------------------------------------------------------------------------
# Pads:  (ref, x, y, net, label)   net=None -> not routed (NC)
# C3 left column bottom->top:  G0 G1 G2 G3 G4 3V3 GND 5V
# C3 right column bottom->top: G21 G20 G10 G9 G8 G7 G6 G5
# CC1101 bottom->top:          GND GDO2 GDO0 3V3 SCK CSN MOSI MISO
# ----------------------------------------------------------------------------
pads = []

def add_pad(ref, x, y, net, label):
    pads.append(dict(ref=ref, x=x, y=y, net=net, label=label))

# C3 left
c3l = [("L0", "NC", ""), ("L1", "NC", ""), ("L2", "NC", ""), ("L3", "GDO2", "GDO2"),
       ("L4", "SCK", "SCK"), ("L5", "3V3", "3V3"), ("L6", "GND", "GND"), ("L7", "NC", "5V")]
for i, (ref, net, lab) in enumerate(c3l):
    add_pad(ref, X_C3L, PY[i], None if net == "NC" else net, lab)

# C3 right
c3r = [("R0", "NC", ""), ("R1", "NC", ""), ("R2", "GDO0", "GDO0"), ("R3", "NC", ""),
       ("R4", "NC", ""), ("R5", "CSN", "CSN"), ("R6", "MOSI", "MOSI"), ("R7", "MISO", "MISO")]
for i, (ref, net, lab) in enumerate(c3r):
    add_pad(ref, X_C3R, PY[i], None if net == "NC" else net, lab)

# CC1101 2x4 (nRF24 pinout). Rows aligned to C3 rows PY[2..5].
# pin1 GND (L,bottom)  pin2 VCC (R,bottom)
# pin3 GDO0(L)         pin4 CSN (R)
# pin5 SCK (L)         pin6 MOSI(R)
# pin7 MISO(L,top)     pin8 GDO2(R,top)
CCY = [PY[2], PY[3], PY[4], PY[5]]        # 9.19, 11.73, 14.27, 16.81
add_pad("P1", X_CCL, CCY[0], "GND",  "GND")
add_pad("P2", X_CCR, CCY[0], "3V3",  "VCC")
add_pad("P3", X_CCL, CCY[1], "GDO0", "GDO0")
add_pad("P4", X_CCR, CCY[1], "CSN",  "CSN")
add_pad("P5", X_CCL, CCY[2], "SCK",  "SCK")
add_pad("P6", X_CCR, CCY[2], "MOSI", "MOSI")
add_pad("P7", X_CCL, CCY[3], "MISO", "MISO")
add_pad("P8", X_CCR, CCY[3], "GDO2", "GDO2")

def P(ref):
    for p in pads:
        if p["ref"] == ref:
            return (p["x"], p["y"])
    raise KeyError(ref)

# ----------------------------------------------------------------------------
# Traces:  dict(layer, net, width, pts=[(x,y)...])
# layer: 'F' top, 'B' bottom
# ----------------------------------------------------------------------------
traces = []
vias = []
def trace(layer, net, width, pts):
    traces.append(dict(layer=layer, net=net, width=width, pts=pts))

def route(net, width, pts):
    """Rectilinear route: horizontals on TOP(F), verticals on BOTTOM(B),
    a via at every H<->V corner. Endpoints are PTH pads (both layers)."""
    for (x1, y1), (x2, y2) in zip(pts[:-1], pts[1:]):
        if abs(y2 - y1) < 1e-9:
            trace("F", net, width, [(x1, y1), (x2, y2)])
        elif abs(x2 - x1) < 1e-9:
            trace("B", net, width, [(x1, y1), (x2, y2)])
        else:
            raise ValueError(f"non-rectilinear seg in {net}: {(x1,y1)}->{(x2,y2)}")
    for i in range(1, len(pts) - 1):
        h1 = abs(pts[i][1] - pts[i-1][1]) < 1e-9
        h2 = abs(pts[i+1][1] - pts[i][1]) < 1e-9
        if h1 != h2:
            vias.append(dict(x=pts[i][0], y=pts[i][1], net=net))

# C3 right-column gap Y's: 20.62, 18.08, 15.54, 13.0, 10.46, 7.92 ...
# Routing: left-col CC dests approached from the channel; right-col CC dests
# approached from the right edge. Long cross-channel runs sit on gap lanes.
route("GND",  TRACE_PWR, [P("L6"), (8,19.35), (8,20.62), (30,20.62), (30,9.19), (X_CCL,9.19)])
route("3V3",  TRACE_SIG, [P("L5"), (8,16.81), (8,18.08), (38,18.08), (38,9.19), (X_CCR,9.19)])
route("SCK",  TRACE_SIG, [P("L4"), (8,14.27), (8,13.0),  (29,13.0),  (29,14.27),(X_CCL,14.27)])
route("GDO2", TRACE_SIG, [P("L3"), (8,11.73), (8,10.46), (37,10.46), (37,16.81),(X_CCR,16.81)])
route("MISO", TRACE_SIG, [P("R7"), (28,21.89), (28,16.81), (X_CCL,16.81)])
route("MOSI", TRACE_SIG, [P("R6"), (39,19.35), (39,14.27), (X_CCR,14.27)])
route("CSN",  TRACE_SIG, [P("R5"), (26,16.81), (26,15.54), (41,15.54), (41,11.73),(X_CCR,11.73)])
route("GDO0", TRACE_SIG, [P("R2"), (28,9.19), (28,11.73), (X_CCL,11.73)])

# ----------------------------------------------------------------------------
# Mounting holes (NPTH, M2)
# ----------------------------------------------------------------------------
mholes = [(2.5, 2.5), (2.5, 23.5), (41.5, 23.5), (41.5, 2.5)]

# ----------------------------------------------------------------------------
# Geometry helpers for DRC / preview
# ----------------------------------------------------------------------------
def seg_pts(tr):
    return list(zip(tr["pts"][:-1], tr["pts"][1:]))

def pt_seg_dist(p, a, b):
    px, py = p; ax, ay = a; bx, by = b
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    cx, cy = ax + t * dx, ay + t * dy
    return math.hypot(px - cx, py - cy)

def seg_seg_dist(a1, a2, b1, b2):
    def ccw(A, B, C):
        return (C[1]-A[1])*(B[0]-A[0]) - (B[1]-A[1])*(C[0]-A[0])
    d1 = ccw(a1, a2, b1); d2 = ccw(a1, a2, b2)
    d3 = ccw(b1, b2, a1); d4 = ccw(b1, b2, a2)
    if ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0)):
        return 0.0
    return min(pt_seg_dist(a1, b1, b2), pt_seg_dist(a2, b1, b2),
              pt_seg_dist(b1, a1, a2), pt_seg_dist(b2, a1, a2))

# ----------------------------------------------------------------------------
# DRC
# ----------------------------------------------------------------------------
def drc():
    errs = []
    # 1) trace <-> trace, same layer, different net
    for i in range(len(traces)):
        for j in range(i + 1, len(traces)):
            t1, t2 = traces[i], traces[j]
            if t1["layer"] != t2["layer"] or t1["net"] == t2["net"]:
                continue
            need = CLEAR + t1["width"]/2 + t2["width"]/2
            for a1, a2 in seg_pts(t1):
                for b1, b2 in seg_pts(t2):
                    d = seg_seg_dist(a1, a2, b1, b2)
                    if d < need - 1e-6:
                        errs.append(f"TRACE/TRACE {t1['net']}({t1['layer']}) vs "
                                    f"{t2['net']}({t2['layer']}): {d:.3f} < {need:.3f} "
                                    f"near {a1}->{a2} / {b1}->{b2}")
    # 2) trace <-> pad (pads are on both layers; different net)
    for t in traces:
        need = CLEAR + t["width"]/2 + PAD_OD/2
        for p in pads:
            if p["net"] == t["net"]:
                continue
            for a1, a2 in seg_pts(t):
                d = pt_seg_dist((p["x"], p["y"]), a1, a2)
                if d < need - 1e-6:
                    errs.append(f"TRACE/PAD {t['net']}({t['layer']}) vs pad "
                                f"{p['ref']}/{p['net']}: {d:.3f} < {need:.3f}")
                    break
    # 3) trace <-> via (both layers; different net)
    for t in traces:
        need = CLEAR + t["width"]/2 + VIA_OD/2
        for v in vias:
            if v["net"] == t["net"]:
                continue
            for a1, a2 in seg_pts(t):
                d = pt_seg_dist((v["x"], v["y"]), a1, a2)
                if d < need - 1e-6:
                    errs.append(f"TRACE/VIA {t['net']} vs via {v['net']}: "
                                f"{d:.3f} < {need:.3f}")
                    break
    # 4) pad <-> pad spacing (center distance vs copper)
    for i in range(len(pads)):
        for j in range(i + 1, len(pads)):
            p, q = pads[i], pads[j]
            if p["net"] and p["net"] == q["net"]:
                continue
            d = math.hypot(p["x"]-q["x"], p["y"]-q["y"])
            need = CLEAR + PAD_OD
            if d < need - 1e-6:
                errs.append(f"PAD/PAD {p['ref']} vs {q['ref']}: {d:.3f} < {need:.3f}")
    # 5) mounting holes vs copper (pads/traces/vias) and board edge
    for (mx, my) in mholes:
        r = MH_DRILL/2
        for p in pads:
            d = math.hypot(p["x"]-mx, p["y"]-my)
            if d < r + PAD_OD/2 + CLEAR - 1e-6:
                errs.append(f"MH({mx},{my}) too close to pad {p['ref']}: {d:.3f}")
        for t in traces:
            need = r + t["width"]/2 + CLEAR
            for a1, a2 in seg_pts(t):
                if pt_seg_dist((mx, my), a1, a2) < need - 1e-6:
                    errs.append(f"MH({mx},{my}) too close to trace {t['net']}")
                    break
        if mx - r < 0.5 or mx + r > BOARD_W-0.5 or my - r < 0.5 or my + r > BOARD_H-0.5:
            errs.append(f"MH({mx},{my}) too close to board edge")
    # 6) pads / traces inside board
    for p in pads:
        if not (PAD_OD/2 < p["x"] < BOARD_W-PAD_OD/2 and PAD_OD/2 < p["y"] < BOARD_H-PAD_OD/2):
            errs.append(f"PAD {p['ref']} outside board")
    return errs

# ----------------------------------------------------------------------------
# Gerber writing (RS-274X, metric, 4.6)
# ----------------------------------------------------------------------------
SCALE = 1_000_000  # mm -> gerber integer units (nm)
def gc(v):
    return str(int(round(v * SCALE)))

class Gerber:
    def __init__(self):
        self.ap = {}
        self.ap_order = []
        self.body = []
        self._next = 10
    def aperture(self, kind, *params):
        key = (kind, params)
        if key not in self.ap:
            code = self._next; self._next += 1
            self.ap[key] = code; self.ap_order.append((code, kind, params))
        return self.ap[key]
    def flash_circle(self, x, y, dia):
        c = self.aperture("C", round(dia, 4))
        self.body.append(f"D{c}*")
        self.body.append(f"X{gc(x)}Y{gc(y)}D03*")
    def draw(self, pts, width):
        c = self.aperture("C", round(width, 4))
        self.body.append(f"D{c}*")
        x0, y0 = pts[0]
        self.body.append(f"X{gc(x0)}Y{gc(y0)}D02*")
        for (x, y) in pts[1:]:
            self.body.append(f"X{gc(x)}Y{gc(y)}D01*")
    def render(self, name):
        out = []
        out.append("%FSLAX46Y46*%")
        out.append("%MOMM*%")
        out.append(f"G04 {name}*")
        out.append("%LPD*%")
        for code, kind, params in self.ap_order:
            if kind == "C":
                out.append(f"%ADD{code}C,{params[0]}*%")
            elif kind == "R":
                out.append(f"%ADD{code}R,{params[0]}X{params[1]}*%")
        out.append("G01*")
        out += self.body
        out.append("M02*")
        return "\n".join(out) + "\n"

# ----------------------------------------------------------------------------
# Stroke font (uppercase, digits, '-', '.', '/'), 5x7 grid
# ----------------------------------------------------------------------------
GL = {
 'A': [[(0,0),(0,5),(2.5,7),(5,5),(5,0)],[(0,3),(5,3)]],
 'B': [[(0,0),(0,7),(3.5,7),(5,6),(5,4.5),(3.5,3.5),(0,3.5)],[(3.5,3.5),(5,2.5),(5,1),(3.5,0),(0,0)]],
 'C': [[(5,6),(3,7),(1,6),(0,4),(0,3),(1,1),(3,0),(5,1)]],
 'D': [[(0,0),(0,7),(3,7),(5,5),(5,2),(3,0),(0,0)]],
 'E': [[(5,7),(0,7),(0,0),(5,0)],[(0,3.5),(3.5,3.5)]],
 'F': [[(5,7),(0,7),(0,0)],[(0,3.5),(3.5,3.5)]],
 'G': [[(5,6),(3,7),(1,6),(0,4),(0,3),(1,1),(3,0),(5,1),(5,3),(3,3)]],
 'H': [[(0,0),(0,7)],[(5,0),(5,7)],[(0,3.5),(5,3.5)]],
 'I': [[(1,7),(4,7)],[(2.5,7),(2.5,0)],[(1,0),(4,0)]],
 'J': [[(5,7),(5,1),(4,0),(2,0),(1,1.5)]],
 'K': [[(0,0),(0,7)],[(5,7),(0,3.5),(5,0)]],
 'L': [[(0,7),(0,0),(5,0)]],
 'M': [[(0,0),(0,7),(2.5,4),(5,7),(5,0)]],
 'N': [[(0,0),(0,7),(5,0),(5,7)]],
 'O': [[(1,1),(1,6),(2.5,7),(4,6),(4,1),(2.5,0),(1,1)]],
 'P': [[(0,0),(0,7),(3.5,7),(5,6),(5,4.5),(3.5,3.5),(0,3.5)]],
 'Q': [[(1,1),(1,6),(2.5,7),(4,6),(4,1),(2.5,0),(1,1)],[(3,1.5),(5,-0.3)]],
 'R': [[(0,0),(0,7),(3.5,7),(5,6),(5,4.5),(3.5,3.5),(0,3.5)],[(2.5,3.5),(5,0)]],
 'S': [[(5,6),(3,7),(1,6),(1,5),(4,2),(4,1),(2,0),(0,1)]],
 'T': [[(0,7),(5,7)],[(2.5,7),(2.5,0)]],
 'U': [[(0,7),(0,1),(1,0),(4,0),(5,1),(5,7)]],
 'V': [[(0,7),(2.5,0),(5,7)]],
 'W': [[(0,7),(1,0),(2.5,4),(4,0),(5,7)]],
 'X': [[(0,0),(5,7)],[(0,7),(5,0)]],
 'Y': [[(0,7),(2.5,3.5),(5,7)],[(2.5,3.5),(2.5,0)]],
 'Z': [[(0,7),(5,7),(0,0),(5,0)]],
 '0': [[(1,1),(1,6),(2.5,7),(4,6),(4,1),(2.5,0),(1,1)],[(1,1),(4,6)]],
 '1': [[(1,5),(2.5,7),(2.5,0)],[(1,0),(4,0)]],
 '2': [[(0,6),(2,7),(4,6),(4,5),(0,0),(5,0)]],
 '3': [[(0,6),(2,7),(4,6),(2.5,3.8),(4,2),(4,1),(2,0),(0,1)]],
 '4': [[(4,0),(4,7),(0,2.5),(5,2.5)]],
 '5': [[(5,7),(0,7),(0,4),(3,4.5),(4.5,3),(4,1),(2,0),(0,1)]],
 '6': [[(4,6),(2,7),(0,4),(0,1),(2,0),(4,1),(4,2.5),(2,3.5),(0,2.5)]],
 '7': [[(0,7),(5,7),(2,0)]],
 '8': [[(2.5,3.6),(1,4.5),(1,6),(2.5,7),(4,6),(4,4.5),(2.5,3.6),(1,2.5),(1,1),(2.5,0),(4,1),(4,2.5),(2.5,3.6)]],
 '9': [[(1,1),(3,0),(5,3),(5,6),(3,7),(1,6),(1,4.5),(3,3.5),(5,4.5)]],
 '-': [[(1,3.5),(4,3.5)]],
 '.': [[(2,0),(2.6,0),(2.6,0.6),(2,0.6),(2,0)]],
 '/': [[(0,0),(5,7)]],
 ' ': [],
}

def text_strokes(s, x, y, h, anchor="l"):
    """Return list of polylines (mm) rendering string s. anchor l/c/r."""
    sc = h / 7.0
    cw = 5 * sc
    adv = (5 + 2) * sc
    total = len(s) * adv - 2 * sc
    if anchor == "c":
        x -= total / 2
    elif anchor == "r":
        x -= total
    out = []
    cx = x
    for ch in s.upper():
        g = GL.get(ch, GL[' '])
        for poly in g:
            out.append([(cx + px * sc, y + py * sc) for (px, py) in poly])
        cx += adv
    return out

# ----------------------------------------------------------------------------
# Build layers
# ----------------------------------------------------------------------------
def build():
    fcu, bcu, fmask, bmask, fsilk, edge = Gerber(), Gerber(), Gerber(), Gerber(), Gerber(), Gerber()

    # copper traces
    for t in traces:
        (fcu if t["layer"] == "F" else bcu).draw(t["pts"], t["width"])
    # pads: copper on both layers + mask openings both sides
    for p in pads:
        fcu.flash_circle(p["x"], p["y"], PAD_OD)
        bcu.flash_circle(p["x"], p["y"], PAD_OD)
        fmask.flash_circle(p["x"], p["y"], PAD_OD + 2*MASK_EXPAND)
        bmask.flash_circle(p["x"], p["y"], PAD_OD + 2*MASK_EXPAND)
    # vias
    for v in vias:
        fcu.flash_circle(v["x"], v["y"], VIA_OD)
        bcu.flash_circle(v["x"], v["y"], VIA_OD)
        fmask.flash_circle(v["x"], v["y"], VIA_OD + 2*MASK_EXPAND)
        bmask.flash_circle(v["x"], v["y"], VIA_OD + 2*MASK_EXPAND)

    # board outline
    edge.draw([(0,0),(BOARD_W,0),(BOARD_W,BOARD_H),(0,BOARD_H),(0,0)], 0.15)

    # --- silkscreen ---
    def silk(strokes):
        for poly in strokes:
            if len(poly) >= 2:
                fsilk.draw(poly, 0.15)
    # titles
    silk(text_strokes("RASPYJACK CC1101-USB", 2.0, BOARD_H-2.2, 1.5))
    silk(text_strokes("ESP32-C3", X_C3L+1.0, 0.6, 1.3))
    silk(text_strokes("CC1101", X_CCL-1.0, 0.6, 1.3))
    # pin labels (near used pads)
    for p in pads:
        if not p["label"]:
            continue
        if p["x"] in (X_C3L, X_CCL):   # left of these pads
            silk(text_strokes(p["label"], p["x"]-1.4, p["y"]-0.5, 0.95, anchor="r"))
        else:                          # right of these pads
            silk(text_strokes(p["label"], p["x"]+1.4, p["y"]-0.5, 0.95, anchor="l"))
    # pin-1 markers (tick) at pin 1 of each connector
    for (xx, yy) in [(X_C3L, PY[0]), (X_C3R, PY[0]), (X_CCL, CCY[0])]:
        silk([[ (xx-1.0, yy-1.0), (xx-1.0, yy-1.6), (xx-0.4, yy-1.6) ]])

    return dict(fcu=fcu, bcu=bcu, fmask=fmask, bmask=bmask, fsilk=fsilk, edge=edge)

# ----------------------------------------------------------------------------
# Excellon drill
# ----------------------------------------------------------------------------
def excellon(holes_by_dia):
    out = ["M48", "METRIC,TZ", "FMAT,2"]
    tools = {}
    for i, dia in enumerate(sorted(holes_by_dia), start=1):
        tools[dia] = i
        out.append(f"T{i}C{dia:.3f}")
    out.append("%")
    out.append("G90"); out.append("G05")
    for dia in sorted(holes_by_dia):
        out.append(f"T{tools[dia]}")
        for (x, y) in holes_by_dia[dia]:
            out.append(f"X{x:.3f}Y{y:.3f}")
    out.append("M30")
    return "\n".join(out) + "\n"

# ----------------------------------------------------------------------------
# SVG preview
# ----------------------------------------------------------------------------
def svg_preview(path):
    sc = 20  # px per mm
    W, H = BOARD_W*sc, BOARD_H*sc
    def X(x): return x*sc
    def Y(y): return (BOARD_H-y)*sc  # flip
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}">']
    s.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="#0b3d1e"/>')
    def line(p, col, w):
        d = " ".join(f"{X(x):.1f},{Y(y):.1f}" for x,y in p)
        s.append(f'<polyline points="{d}" fill="none" stroke="{col}" '
                 f'stroke-width="{w*sc:.1f}" stroke-linecap="round" stroke-linejoin="round"/>')
    for t in traces:
        line(t["pts"], "#d98f1a" if t["layer"]=="F" else "#6a7cff", t["width"])
    for p in pads:
        s.append(f'<circle cx="{X(p["x"]):.1f}" cy="{Y(p["y"]):.1f}" r="{PAD_OD/2*sc:.1f}" '
                 f'fill="#c9a227" stroke="#111" stroke-width="1"/>')
        s.append(f'<circle cx="{X(p["x"]):.1f}" cy="{Y(p["y"]):.1f}" r="{PAD_DRILL/2*sc:.1f}" fill="#0b3d1e"/>')
    for v in vias:
        s.append(f'<circle cx="{X(v["x"]):.1f}" cy="{Y(v["y"]):.1f}" r="{VIA_OD/2*sc:.1f}" fill="#999"/>')
    for (mx,my) in mholes:
        s.append(f'<circle cx="{X(mx):.1f}" cy="{Y(my):.1f}" r="{MH_DRILL/2*sc:.1f}" '
                 f'fill="#0b3d1e" stroke="#ccc" stroke-width="1.5"/>')
    # silk (white) for labels
    layers = build()
    s.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="none" stroke="#eee" stroke-width="2"/>')
    # redraw silk polylines from fsilk body is complex; re-render strokes directly:
    for poly in _silk_cache:
        if len(poly) >= 2:
            line(poly, "#ffffff", 0.15)
    s.append("</svg>")
    with open(path, "w") as f:
        f.write("\n".join(s))

_silk_cache = []

# hook silk strokes for preview
def build_with_cache():
    global _silk_cache
    _silk_cache = []
    orig = Gerber.draw
    return build()

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    gdir = os.path.join(here, "gerbers")
    os.makedirs(gdir, exist_ok=True)

    errs = drc()
    print("DRC:", "PASS" if not errs else f"{len(errs)} VIOLATION(S)")
    for e in errs:
        print("  !", e)

    # collect silk strokes for preview (recompute strings used in build)
    global _silk_cache
    _silk_cache = []
    _silk_cache += text_strokes("RASPYJACK CC1101-USB", 2.0, BOARD_H-2.2, 1.5)
    _silk_cache += text_strokes("ESP32-C3", X_C3L+1.0, 0.6, 1.3)
    _silk_cache += text_strokes("CC1101", X_CCL-1.0, 0.6, 1.3)
    for p in pads:
        if not p["label"]:
            continue
        if p["x"] in (X_C3L, X_CCL):
            _silk_cache += text_strokes(p["label"], p["x"]-1.4, p["y"]-0.5, 0.95, anchor="r")
        else:
            _silk_cache += text_strokes(p["label"], p["x"]+1.4, p["y"]-0.5, 0.95, anchor="l")

    layers = build()
    files = {
        "raspyjack-cc1101-F_Cu.gbr": layers["fcu"].render("F.Cu"),
        "raspyjack-cc1101-B_Cu.gbr": layers["bcu"].render("B.Cu"),
        "raspyjack-cc1101-F_Mask.gbr": layers["fmask"].render("F.Mask"),
        "raspyjack-cc1101-B_Mask.gbr": layers["bmask"].render("B.Mask"),
        "raspyjack-cc1101-F_Silkscreen.gbr": layers["fsilk"].render("F.Silkscreen"),
        "raspyjack-cc1101-Edge_Cuts.gbr": layers["edge"].render("Edge.Cuts"),
    }
    for name, data in files.items():
        with open(os.path.join(gdir, name), "w") as f:
            f.write(data)

    # drills
    pth = {PAD_DRILL: [(p["x"], p["y"]) for p in pads],
           VIA_DRILL: [(v["x"], v["y"]) for v in vias]}
    npth = {MH_DRILL: list(mholes)}
    with open(os.path.join(gdir, "raspyjack-cc1101-PTH.drl"), "w") as f:
        f.write(excellon(pth))
    with open(os.path.join(gdir, "raspyjack-cc1101-NPTH.drl"), "w") as f:
        f.write(excellon(npth))

    svg_preview(os.path.join(here, "preview.svg"))
    print("Wrote", len(files)+2, "gerber/drill files to", gdir)
    print("Wrote preview.svg")
    return 0 if not errs else 1

if __name__ == "__main__":
    raise SystemExit(main())
