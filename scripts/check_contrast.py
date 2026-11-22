"""Verify WCAG 2.x contrast of the design tokens (design-system.md §2).

Parses ``frontend/src/styles/tokens.css`` (the source of truth), resolves ``var()``
references per theme, composites translucent colours over their background, and checks
every text/UI pairing the design system promises. Exits non-zero on any failure.

    python scripts/check_contrast.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple

TOKENS = Path(__file__).resolve().parents[1] / "frontend" / "src" / "styles" / "tokens.css"

RGB = tuple[float, float, float]


class Pair(NamedTuple):
    fg: str
    bg: str
    minimum: float
    label: str


TEXT, UI = 4.5, 3.0
PAIRS: list[Pair] = [
    Pair("color-text", "color-bg", TEXT, "text on bg"),
    Pair("color-text", "color-surface", TEXT, "text on surface"),
    Pair("color-text", "color-surface-raised", TEXT, "text on raised surface"),
    Pair("color-text-muted", "color-bg", TEXT, "muted text on bg"),
    Pair("color-text-muted", "color-surface", TEXT, "muted text on surface"),
    Pair("color-text-muted", "color-surface-raised", TEXT, "muted text on raised surface"),
    Pair("color-on-primary", "color-primary", TEXT, "primary button label"),
    Pair("color-on-primary", "color-primary-hover", TEXT, "primary button label (hover)"),
    Pair("color-accent-text", "color-bg", TEXT, "accent text on bg"),
    Pair("color-focus", "color-bg", UI, "focus ring on bg"),
    Pair("color-focus", "color-surface", UI, "focus ring on surface"),
    Pair("color-border-strong", "color-bg", UI, "strong border on bg"),
    Pair("color-border-strong", "color-surface", UI, "strong border on surface"),
    Pair("color-ai", "color-surface", TEXT, "AI text on surface"),
    Pair("color-success", "color-surface", UI, "success icon on surface"),
    Pair("color-danger", "color-surface", TEXT, "danger text on surface"),
    Pair("color-warning", "color-surface", UI, "warning icon on surface"),
]
for sev in ("critical", "high", "medium", "low", "info"):
    PAIRS.append(Pair(f"color-sev-{sev}", "color-surface", TEXT, f"{sev} text on surface"))
    PAIRS.append(Pair(f"color-sev-{sev}", f"color-sev-{sev}-bg@color-surface", TEXT, f"{sev} badge"))
PAIRS.append(Pair("color-ai", "color-ai-bg@color-surface", TEXT, "AI caption in AI panel"))
PAIRS.append(Pair("color-text", "color-ai-bg@color-surface", TEXT, "text in AI panel"))
PAIRS.append(Pair("color-danger", "color-danger-bg@color-surface", TEXT, "danger button label"))
PAIRS.append(Pair("color-bg", "color-text", TEXT, "confirmed status badge (inverted)"))


def _blocks(css: str) -> dict[str, dict[str, str]]:
    """Map theme -> {var: raw value}. Dark values come from ':root' blocks."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    themes: dict[str, dict[str, str]] = {"dark": {}, "light": {}}
    for selector, body in re.findall(r"([^{}@]+)\{([^{}]*)\}", css):
        decls = dict(re.findall(r"--([\w-]+)\s*:\s*([^;]+);", body))
        sel = selector.strip()
        if 'data-theme="light"' in sel and "system" not in sel:
            themes["light"].update(decls)
        elif sel.startswith(":root") and "data-density" not in sel and "system" not in sel:
            themes["dark"].update(decls)
    # Light inherits raw scales and anything it doesn't override.
    themes["light"] = {**themes["dark"], **themes["light"]}
    return themes


def _resolve(name: str, decls: dict[str, str], depth: int = 0) -> str:
    value = decls[name].strip()
    m = re.fullmatch(r"var\(--([\w-]+)\)", value)
    if m and depth < 10:
        return _resolve(m.group(1), decls, depth + 1)
    return value


def _parse(value: str) -> tuple[RGB, float]:
    value = value.strip().lower()
    if value.startswith("#"):
        h = value[1:]
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
        return (r, g, b), 1.0
    m = re.fullmatch(r"rgb\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:/\s*([\d.]+%?))?\s*\)", value)
    if not m:
        raise ValueError(f"unsupported colour {value!r}")
    alpha_raw = m.group(4)
    if alpha_raw is None:
        alpha = 1.0
    elif alpha_raw.endswith("%"):
        alpha = float(alpha_raw[:-1]) / 100
    else:
        alpha = float(alpha_raw)
    return (float(m.group(1)) / 255, float(m.group(2)) / 255, float(m.group(3)) / 255), alpha


def _over(top: tuple[RGB, float], bottom: RGB) -> RGB:
    (r, g, b), a = top
    return (r * a + bottom[0] * (1 - a), g * a + bottom[1] * (1 - a), b * a + bottom[2] * (1 - a))


def _colour(spec: str, decls: dict[str, str]) -> RGB:
    """``name`` or ``name@backdrop`` (translucent token composited over a backdrop)."""
    if "@" in spec:
        name, backdrop = spec.split("@", 1)
        return _over(_parse(_resolve(name, decls)), _colour(backdrop, decls))
    rgb, alpha = _parse(_resolve(spec, decls))
    if alpha < 1:
        return _over((rgb, alpha), _colour("color-bg", decls))
    return rgb


def _luminance(rgb: RGB) -> float:
    def ch(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (ch(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: RGB, b: RGB) -> float:
    """WCAG 2.x contrast ratio."""
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    """Print a table per theme; return 1 if any pairing fails."""
    themes = _blocks(TOKENS.read_text(encoding="utf-8"))
    failures = 0
    for theme, decls in themes.items():
        sys.stdout.write(f"\n{theme.upper()}\n")
        for pair in PAIRS:
            ratio = contrast(_colour(pair.fg, decls), _colour(pair.bg, decls))
            ok = ratio >= pair.minimum
            failures += not ok
            mark = "ok  " if ok else "FAIL"
            sys.stdout.write(f"  {mark} {ratio:5.2f} (>= {pair.minimum}) {pair.label}\n")
    sys.stdout.write(f"\n{'All pairings pass.' if not failures else f'{failures} failing pairing(s).'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
