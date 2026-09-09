"""Shared visual system for the Network IDS application."""

# Surfaces — near-black operations console
MATRIX_BG = "#050806"
DARK_GREEN = "#0C1410"
SURFACE = "#132018"
BORDER = "#1E3A28"

# Text
MATRIX_GREEN = "#D7F5E2"
MUTED = "#7F9A88"

# Accent and actions
ACCENT_GREEN = "#3DDC97"
ACCENT_HOVER = "#2BB673"
BUTTON_BG = "#163528"
BUTTON_FG = "#E8FFF3"

# Status
RED = "#F07178"
GREEN = "#34D399"
BLUE = "#60A5FA"
PURPLE = "#A78BFA"
AMBER = "#F5B942"

MODERN_BG = MATRIX_BG
MODERN_FG = MATRIX_GREEN
ACCENT_COLOR = ACCENT_GREEN

FONT_UI = "DejaVu Sans"
FONT_MONO = "DejaVu Sans Mono"


def ui_font(size=10, bold=False):
    """Tcl-safe font spec. Family names with spaces must be braced."""
    weight = " bold" if bold else ""
    return f"{{{FONT_UI}}} {size}{weight}"


def mono_font(size=10, bold=False):
    weight = " bold" if bold else ""
    return f"{{{FONT_MONO}}} {size}{weight}"

CHART_IN = "#3DDC97"
CHART_OUT = "#F5B942"
PROTOCOL_COLORS = {
    "TCP": "#3B82F6",
    "UDP": "#34D399",
    "ICMP": "#F5B942",
    "ARP": "#A78BFA",
    "802.11": "#F43F5E",
}
