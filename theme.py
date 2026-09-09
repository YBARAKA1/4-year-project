"""Apply a consistent professional theme to Tk and ttk widgets."""

import tkinter as tk
from tkinter import ttk

from constants import (
    ACCENT_GREEN,
    BORDER,
    BUTTON_BG,
    BUTTON_FG,
    DARK_GREEN,
    MATRIX_BG,
    MATRIX_GREEN,
    MUTED,
    SURFACE,
    mono_font,
    ui_font,
)


def apply_theme(root=None):
    """Configure the application-wide ttk theme and common widget defaults."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        ".",
        background=MATRIX_BG,
        foreground=MATRIX_GREEN,
        fieldbackground=DARK_GREEN,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        font=ui_font(10),
        troughcolor=SURFACE,
    )

    style.configure("TFrame", background=MATRIX_BG)
    style.configure("TLabel", background=MATRIX_BG, foreground=MATRIX_GREEN, font=ui_font(10))
    style.configure("Header.TLabel", background=MATRIX_BG, foreground=MATRIX_GREEN, font=ui_font(13, bold=True), padding=(4, 8))
    style.configure("Muted.TLabel", background=MATRIX_BG, foreground=MUTED, font=ui_font(9))
    style.configure("Sidebar.TFrame", background=DARK_GREEN)
    style.configure("SidebarHeader.TLabel", background=DARK_GREEN, foreground=ACCENT_GREEN, font=mono_font(13, bold=True), padding=(8, 6))
    style.configure("SidebarMuted.TLabel", background=DARK_GREEN, foreground=MUTED, font=mono_font(9))

    style.configure(
        "TButton",
        background=BUTTON_BG,
        foreground=BUTTON_FG,
        font=ui_font(10, bold=True),
        padding=(12, 8),
        borderwidth=0,
        focuscolor=ACCENT_GREEN,
    )
    style.map(
        "TButton",
        background=[("active", ACCENT_GREEN), ("disabled", SURFACE)],
        foreground=[("active", BUTTON_FG), ("disabled", MUTED)],
    )

    style.configure(
        "Sidebar.TButton",
        background=DARK_GREEN,
        foreground=MATRIX_GREEN,
        font=mono_font(10),
        padding=(14, 10),
        borderwidth=0,
        anchor="w",
    )
    style.map(
        "Sidebar.TButton",
        background=[("active", SURFACE), ("disabled", DARK_GREEN)],
        foreground=[("active", MATRIX_GREEN), ("disabled", MUTED)],
    )
    style.configure(
        "SidebarActive.TButton",
        background=ACCENT_GREEN,
        foreground=BUTTON_FG,
        font=mono_font(10, bold=True),
        padding=(14, 10),
        borderwidth=0,
        anchor="w",
    )
    style.map(
        "SidebarActive.TButton",
        background=[("active", ACCENT_GREEN), ("disabled", SURFACE)],
        foreground=[("active", BUTTON_FG), ("disabled", MUTED)],
    )

    style.configure(
        "Treeview",
        background=DARK_GREEN,
        foreground=MATRIX_GREEN,
        fieldbackground=DARK_GREEN,
        borderwidth=0,
        rowheight=28,
        font=ui_font(10),
    )
    style.configure(
        "Treeview.Heading",
        background=SURFACE,
        foreground=MATRIX_GREEN,
        font=ui_font(10, bold=True),
        relief="flat",
        padding=(8, 6),
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT_GREEN)],
        foreground=[("selected", BUTTON_FG)],
    )
    style.map("Treeview.Heading", background=[("active", SURFACE)])

    style.configure("TNotebook", background=MATRIX_BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED, padding=(14, 8), font=ui_font(10))
    style.map(
        "TNotebook.Tab",
        background=[("selected", DARK_GREEN), ("active", SURFACE)],
        foreground=[("selected", MATRIX_GREEN), ("active", MATRIX_GREEN)],
    )

    style.configure(
        "TEntry",
        fieldbackground=DARK_GREEN,
        foreground=MATRIX_GREEN,
        insertcolor=MATRIX_GREEN,
        bordercolor=BORDER,
        padding=6,
    )
    style.configure(
        "TCombobox",
        fieldbackground=DARK_GREEN,
        background=SURFACE,
        foreground=MATRIX_GREEN,
        arrowcolor=MATRIX_GREEN,
        padding=4,
    )
    style.map("TCombobox", fieldbackground=[("readonly", DARK_GREEN)], foreground=[("readonly", MATRIX_GREEN)])

    style.configure("TLabelframe", background=MATRIX_BG, foreground=MATRIX_GREEN, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=MATRIX_BG, foreground=MATRIX_GREEN, font=ui_font(11, bold=True))
    style.configure("Vertical.TScrollbar", background=SURFACE, troughcolor=MATRIX_BG, arrowcolor=MUTED)
    style.configure("Horizontal.TScrollbar", background=SURFACE, troughcolor=MATRIX_BG, arrowcolor=MUTED)

    if root is not None:
        root.configure(bg=MATRIX_BG)
        root.option_add("*Font", ui_font(10))
        root.option_add("*Menu.background", DARK_GREEN)
        root.option_add("*Menu.foreground", MATRIX_GREEN)
        root.option_add("*Menu.activeBackground", ACCENT_GREEN)
        root.option_add("*Menu.activeForeground", BUTTON_FG)
        root.option_add("*Listbox.background", DARK_GREEN)
        root.option_add("*Listbox.foreground", MATRIX_GREEN)
        root.option_add("*Listbox.selectBackground", ACCENT_GREEN)
        root.option_add("*Listbox.selectForeground", BUTTON_FG)
