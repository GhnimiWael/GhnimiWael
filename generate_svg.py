#!/usr/bin/env python3
import html
import json
import os
import textwrap
import urllib.request
from datetime import date

# ----------------------------------------------------------------------------
# 1. Profile facts  ->  edit here to change the card
#    Source of truth: https://0xw43l.com/about/
# ----------------------------------------------------------------------------
GITHUB_USER   = "GhnimiWael"
PROMPT_USER   = "wael@ghnimi"
PROMPT_CMD    = "./whoami.sh --profile"
TERM_TITLE    = f"{PROMPT_USER}: ~/threat-intel"
CAREER_START  = date(2020, 7, 4)          # drives the "Uptime" field

PANEL = [
    ("host",  PROMPT_USER),
    ("field", "OS",     "Kali Linux, ParrotOS, Windows"),
    ("field", "Uptime", None),            # None -> computed from CAREER_START
    ("field", "Host",   "Senior Cyber Threat Intelligence Analyst"),
    ("field", "Kernel", "Purple Team . CTI . Reverse Engineering"),
    ("field", "Shell",  "zsh . IDA Pro . Ghidra . Caido . Neovim"),
    ("blank",),

    ("rule",  "Certifications"),
    ("field", "Offensive",    "OSEP, CRTO, eWAPTx, eJPT, HTB Dante Pro"),
    ("field", "Intelligence", "arcX CTI 101, ICTTF Ransomware Uncovered"),
    ("field", "In.Progress",  "OSWE, OSED, arcX CTI Practitioner"),
    ("blank",),

    ("rule",  "Stack"),
    ("field", "Languages.Code", "C, C++, Python, PowerShell, Bash"),
    ("field", "Languages.Real", "Arabic, French, English"),
    ("field", "Offensive",      "Cobalt Strike, Burp Suite Pro, BloodHound, Impacket"),
    ("field", "Defensive",      "MISP, OpenCTI, TheHive, QRadar, Splunk, CrowdStrike"),
    ("field", "Reversing",      "IDA Pro, Ghidra, x64dbg, CAPEv2, YARA"),
    ("field", "Frameworks",     "MITRE ATT&CK, Diamond Model, Cyber Kill Chain"),
    ("blank",),

    ("rule",  "Research"),
    ("field", "TACTFlow",         "Purple-team framework - ATT&CK to playbooks"),
    ("field", "LDAPHunter",       "Automated AD / LDAP enumeration"),
    ("field", "Qakbot.Decryptor", "IDA Pro plugin - config + IOC extraction"),
    ("field", "CryptBot.Series",  "3-part infostealer deep dive (v1/v2/v3)"),
    ("field", "DPTML",            "RL-driven pentest automation research"),
    ("blank",),

    ("rule",  "Contact"),
    ("field", "Website",   "0xw43l.com"),
    ("field", "Email",     "wael.ghnimi@hotmail.com"),
    ("field", "LinkedIn",  "in/waelghnimi"),
    ("field", "X.Twitter", "@GhnimiWael"),
    ("field", "GitHub",    GITHUB_USER),
    ("blank",),

    ("rule",  "GitHub Stats"),
    ("stats", ("repos", "stars", "forks")),
    ("stats", ("followers", "following")),
    ("blank",),

    ("prompt",),
]

# Used only when the GitHub API is unreachable (offline regeneration).
STATS_FALLBACK = {"repos": "32", "stars": "149", "forks": "27",
                  "followers": "49", "following": "84"}
STATS_LABELS   = {"repos": "Repos", "stars": "Stars", "forks": "Forks",
                  "followers": "Followers", "following": "Following"}

# ----------------------------------------------------------------------------
# 2. Layout — every dimension below is derived, not hand-tuned
# ----------------------------------------------------------------------------
RADIUS      = 15
BAR_H       = 38
PAD_L       = 22            # left padding before the ASCII block
GAP         = 30            # gap between ASCII block and terminal panel
PAD_R       = 24
PAD_B       = 24

PANEL_FS    = 14
PANEL_LH    = 17.6
CMD_GAP     = 26            # bar bottom -> command baseline, so the prompt clears the chrome
PANEL_Y0    = BAR_H + CMD_GAP

ASCII_FS_MAX = 11.0         # cap so the portrait never dwarfs the panel
ASCII_LH_RATIO = 1.06       # line-height / font-size

ADV         = 0.62          # monospace advance-width / font-size (safe upper bound)

MIN_COLS    = 64            # narrowest the report column may be
MAX_COLS    = 72            # past this, values wrap instead of widening the card
MIN_DOTS    = 2

# ----------------------------------------------------------------------------
# 3. Colour themes (GitHub dark / light palettes)
# ----------------------------------------------------------------------------
THEMES = {
    "dark": {
        "bg": "#0d1117", "bar": "#161b22", "border": "#30363d",
        "fg": "#c9d1d9", "muted": "#7d8590",
        "key": "#ffa657", "value": "#a5d6ff", "cc": "#616e7f",
        "prompt": "#3fb950", "cur": "#a5d6ff",
        "dot_r": "#ff5f56", "dot_y": "#ffbd2e", "dot_g": "#27c93f",
    },
    "light": {
        "bg": "#ffffff", "bar": "#f6f8fa", "border": "#d0d7de",
        "fg": "#1f2328", "muted": "#6e7781",
        "key": "#953800", "value": "#0550ae", "cc": "#8c959f",
        "prompt": "#1a7f37", "cur": "#0550ae",
        "dot_r": "#ff5f56", "dot_y": "#ffbd2e", "dot_g": "#27c93f",
    },
}


# ----------------------------------------------------------------------------
# 4. Data helpers
# ----------------------------------------------------------------------------
def esc(s):
    return html.escape(str(s), quote=False)


def uptime(start, today=None):
    """Human 'Ny, Nm, Nd' since `start` — recomputed on every regeneration."""
    today = today or date.today()
    years = today.year - start.year
    months = today.month - start.month
    days = today.day - start.day
    if days < 0:
        months -= 1
        prev_m, prev_y = (today.month - 1, today.year) if today.month > 1 else (12, today.year - 1)
        days += (date(prev_y + (prev_m == 12), prev_m % 12 + 1, 1)
                 - date(prev_y, prev_m, 1)).days
    if months < 0:
        years -= 1
        months += 12
    return (f"{years} year{'s' * (years != 1)}, {months} month{'s' * (months != 1)}, "
            f"{days} day{'s' * (days != 1)}")


def _api(url):
    # GITHUB_TOKEN lifts the 60/h unauthenticated limit — required in CI, where
    # the runner's IP shares that quota with every other Actions job.
    headers = {"User-Agent": "profile-card"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def github_stats():
    """Live counters, falling back to the cached values when offline."""
    try:
        user = _api(f"https://api.github.com/users/{GITHUB_USER}")
        repos = _api(f"https://api.github.com/users/{GITHUB_USER}/repos"
                     f"?per_page=100&type=owner")
        return {
            "repos":     str(user["public_repos"]),
            "stars":     str(sum(r["stargazers_count"] for r in repos)),
            "forks":     str(sum(r["forks_count"] for r in repos)),
            "followers": str(user["followers"]),
            "following": str(user["following"]),
        }
    except Exception as e:                      # offline / rate-limited / API change
        print(f"  ! GitHub API unavailable ({e.__class__.__name__}), using cached stats")
        return dict(STATS_FALLBACK)


def resolve(panel, stats):
    """Fill computed values in so layout sizing sees the final strings."""
    out = []
    for spec in panel:
        if spec[0] == "field" and spec[1] == "Uptime" and spec[2] is None:
            out.append(("field", "Uptime", uptime(CAREER_START)))
        else:
            out.append(spec)
    return out


# ----------------------------------------------------------------------------
# 5. Row builders — each returns a list of plain-text-width-aware inner spans
# ----------------------------------------------------------------------------
def key_spans(label):
    return '<tspan class="p">.</tspan>'.join(
        f'<tspan class="key">{esc(p)}</tspan>' for p in label.split("."))


def prompt_spans():
    return (f'<tspan class="prompt">{esc(PROMPT_USER)}</tspan>'
            f'<tspan class="p">:</tspan><tspan class="value">~</tspan>'
            f'<tspan class="p">$</tspan> ')


def field_cols(label, value):
    """Columns a field needs on one line: '. Label: .. value'."""
    return 2 + len(label) + 1 + 1 + MIN_DOTS + 1 + len(value)


def field_rows(label, value, cols):
    """One row, or a first row plus right-aligned continuation rows."""
    prefix = 2 + len(label) + 1                       # ". Label:"
    room = cols - prefix - 2 - MIN_DOTS               # space dots space
    chunks = textwrap.wrap(value, max(room, 12), break_long_words=False) or [value]

    dots = max(cols - prefix - 2 - len(chunks[0]), MIN_DOTS)
    rows = [f'<tspan class="cc">. </tspan>{key_spans(label)}<tspan class="p">:</tspan>'
            f'<tspan class="cc"> {"." * dots} </tspan>'
            f'<tspan class="value">{esc(chunks[0])}</tspan>']
    for chunk in chunks[1:]:
        pad = max(cols - len(chunk), 1)
        rows.append(f'<tspan class="cc">{" " * pad}</tspan>'
                    f'<tspan class="value">{esc(chunk)}</tspan>')
    return rows


def host_inner(user, cols):
    return (f'<tspan class="prompt">{esc(user)}</tspan>'
            f'<tspan class="p"> {"—" * max(cols - len(user) - 1, 1)}</tspan>')


def rule_inner(title, cols):
    return (f'<tspan class="p">- </tspan><tspan class="key">{esc(title)}</tspan>'
            f'<tspan class="p"> {"—" * max(cols - len(title) - 3, 1)}</tspan>')


def stats_cols(keys, stats):
    fixed = 2 + sum(len(STATS_LABELS[k]) + 3 + len(stats[k]) for k in keys)
    return fixed + 3 * (len(keys) - 1) + MIN_DOTS * len(keys)


def stats_inner(keys, stats, cols):
    """Same right edge as every other row: pad the dot runs, not the tail."""
    fixed = 2 + sum(len(STATS_LABELS[k]) + 3 + len(stats[k]) for k in keys) \
            + 3 * (len(keys) - 1)
    total_dots = max(cols - fixed, MIN_DOTS * len(keys))
    each, extra = divmod(total_dots, len(keys))

    segs = []
    for i, k in enumerate(keys):
        n = each + (1 if i < extra else 0)
        segs.append(f'<tspan class="key">{STATS_LABELS[k]}</tspan>'
                    f'<tspan class="p">:</tspan>'
                    f'<tspan class="cc"> {"." * n} </tspan>'
                    f'<tspan class="value">{esc(stats[k])}</tspan>')
    return '<tspan class="cc">. </tspan>' + '<tspan class="p"> | </tspan>'.join(segs)


def read_ascii(path="ascci_image.txt"):
    with open(path, encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


# ----------------------------------------------------------------------------
# 6. Compose
# ----------------------------------------------------------------------------
def measure(panel, stats):
    """Report-column width: wide enough for the content, capped at MAX_COLS."""
    need = [MIN_COLS]
    for spec in panel:
        if spec[0] == "field":
            need.append(field_cols(spec[1], spec[2]))
        elif spec[0] == "stats":
            need.append(stats_cols(spec[1], stats))
        elif spec[0] == "rule":
            need.append(len(spec[1]) + 4)
    return min(max(need), MAX_COLS)


def panel_rows(panel, stats, cols):
    """[(kind, inner)] in render order; 'blank' carries no inner."""
    rows = []
    for spec in panel:
        kind = spec[0]
        if kind == "blank":
            rows.append(("blank", None))
        elif kind == "host":
            rows.append(("row", host_inner(spec[1], cols)))
        elif kind == "rule":
            rows.append(("row", rule_inner(spec[1], cols)))
        elif kind == "field":
            rows += [("row", r) for r in field_rows(spec[1], spec[2], cols)]
        elif kind == "stats":
            rows.append(("row", stats_inner(spec[1], stats, cols)))
        elif kind == "prompt":
            rows.append(("prompt", prompt_spans() + '<tspan class="cur">&#9608;</tspan>'))
    return rows


def build(theme_name, panel, stats):
    t = THEMES[theme_name]
    ascii_lines = read_ascii()
    cols = measure(panel, stats)
    rows = panel_rows(panel, stats, cols)

    # --- vertical: panel drives the card height ------------------------------
    y_first = PANEL_Y0 + PANEL_LH * 2                     # blank line after the command
    H = int(round(y_first + (len(rows) - 1) * PANEL_LH + PAD_B))

    # --- horizontal: ASCII block scaled to the height, then capped -----------
    n, maxcol = len(ascii_lines), max((len(l) for l in ascii_lines), default=1)
    avail_h = H - BAR_H - PAD_B * 2
    a_fs = min(ASCII_FS_MAX, avail_h / (n * ASCII_LH_RATIO))
    a_lh = a_fs * ASCII_LH_RATIO
    ascii_w = maxcol * a_fs * ADV
    ascii_y0 = BAR_H + (H - BAR_H - n * a_lh) / 2 + a_fs

    panel_x = int(round(PAD_L + ascii_w + GAP))
    W = int(round(panel_x + cols * PANEL_FS * ADV + PAD_R))

    ascii_rows = [
        f'<text x="{PAD_L}" y="{round(ascii_y0 + i * a_lh, 2)}" class="arow" '
        f'fill="{t["fg"]}" font-size="{round(a_fs, 2)}px" '
        f'style="animation-delay:{round(0.15 + i * 0.018, 3)}s">{esc(ln)}</text>'
        for i, ln in enumerate(ascii_lines)
    ]

    cmd = (f'<text x="{panel_x}" y="{PANEL_Y0}" class="cmd" '
           f'style="animation-delay:0.25s">{prompt_spans()}'
           f'<tspan class="fg">{esc(PROMPT_CMD)}</tspan></text>')

    out_rows, y, i = [], y_first, 0
    for kind, inner in rows:
        if kind == "blank":
            y = round(y + PANEL_LH, 2)
            continue
        cls = "orow" if kind == "row" else "prompt-row"
        delay = round(1.4 + i * 0.06 + (0.25 if kind == "prompt" else 0), 3)
        out_rows.append(f'<text x="{panel_x}" y="{y}" class="{cls}" '
                        f'style="animation-delay:{delay}s">{inner}</text>')
        i += 1
        y = round(y + PANEL_LH, 2)

    style = f"""
    <style>
      text, tspan {{ white-space: pre;
        font-family: 'Consolas','DejaVu Sans Mono','Courier New',monospace; }}
      .fg    {{ fill: {t['fg']}; }}
      .key   {{ fill: {t['key']}; }}
      .value {{ fill: {t['value']}; }}
      .cc    {{ fill: {t['cc']}; }}
      .p     {{ fill: {t['muted']}; }}
      .prompt{{ fill: {t['prompt']}; }}
      .cmd, .orow, .prompt-row {{ fill: {t['fg']}; }}
      .cur   {{ fill: {t['cur']}; }}

      .arow      {{ animation: type .45s steps(26) backwards; }}
      .cmd       {{ animation: type .85s steps(24) backwards; }}
      .orow      {{ animation: type .32s steps(20) backwards; }}
      .prompt-row{{ animation: fade .35s ease-out backwards; }}
      .cur       {{ animation: blink 1.05s steps(1) infinite; }}

      @keyframes type  {{ from {{ clip-path: inset(0 100% 0 0); }}
                          to   {{ clip-path: inset(0 -2px 0 0); }} }}
      @keyframes fade  {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
      @keyframes blink {{ 0%,49% {{ opacity: 1; }} 50%,100% {{ opacity: 0; }} }}

      @media (prefers-reduced-motion: reduce) {{
        .arow, .cmd, .orow, .prompt-row {{ animation: none; clip-path: none; opacity: 1; }}
        .cur {{ animation: none; }}
      }}
    </style>"""

    chrome = f'''
    <rect width="{W}" height="{H}" rx="{RADIUS}" fill="{t['bg']}" stroke="{t['border']}" stroke-width="1"/>
    <path d="M0 {RADIUS} A{RADIUS} {RADIUS} 0 0 1 {RADIUS} 0 L{W-RADIUS} 0 A{RADIUS} {RADIUS} 0 0 1 {W} {RADIUS} L{W} {BAR_H} L0 {BAR_H} Z" fill="{t['bar']}"/>
    <line x1="0" y1="{BAR_H}" x2="{W}" y2="{BAR_H}" stroke="{t['border']}" stroke-width="1"/>
    <circle cx="22" cy="{BAR_H//2}" r="6" fill="{t['dot_r']}"/>
    <circle cx="42" cy="{BAR_H//2}" r="6" fill="{t['dot_y']}"/>
    <circle cx="62" cy="{BAR_H//2}" r="6" fill="{t['dot_g']}"/>
    <text x="{W//2}" y="{BAR_H//2 + 5}" text-anchor="middle" font-size="14px" fill="{t['muted']}">{esc(TERM_TITLE)}</text>'''

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{W}px" height="{H}px" viewBox="0 0 {W} {H}" font-size="{PANEL_FS}px" font-family="'Consolas','DejaVu Sans Mono',monospace">
{style}
{chrome}
{"".join(chr(10) + r for r in ascii_rows)}
{cmd}
{"".join(chr(10) + r for r in out_rows)}
</svg>
'''
    return svg, W, H, cols


if __name__ == "__main__":
    stats = github_stats()
    panel = resolve(PANEL, stats)
    for name in ("dark", "light"):
        svg, W, H, cols = build(name, panel, stats)
        with open(f"{name}_mode.svg", "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"wrote {name}_mode.svg  ({W}x{H}, {cols} cols)")
    print(f"  uptime {uptime(CAREER_START)} | "
          + " ".join(f"{k}={v}" for k, v in stats.items()))
