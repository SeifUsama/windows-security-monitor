"""
app/ui/widgets/severity_badge.py
---------------------------------
Color-coded severity badge label.
"""

import customtkinter as ctk


SEVERITY_STYLES = {
    "CRITICAL": {"bg": "#dc3545", "fg": "#ffffff"},
    "HIGH":     {"bg": "#fd7e14", "fg": "#ffffff"},
    "MEDIUM":   {"bg": "#ffc107", "fg": "#212529"},
    "LOW":      {"bg": "#28a745", "fg": "#ffffff"},
    "INFO":     {"bg": "#6c757d", "fg": "#ffffff"},
}


def severity_to_tag(severity: str) -> str:
    """Return the severity string normalized to uppercase key."""
    return severity.upper() if severity.upper() in SEVERITY_STYLES else "INFO"


def get_severity_colors(severity: str) -> tuple[str, str]:
    """Return (background, foreground) hex colors for a severity."""
    style = SEVERITY_STYLES.get(severity.upper(), SEVERITY_STYLES["INFO"])
    return style["bg"], style["fg"]


class SeverityBadge(ctk.CTkLabel):
    """A small colored label showing severity level."""

    def __init__(self, master, severity: str = "INFO", **kwargs):
        style = SEVERITY_STYLES.get(severity.upper(), SEVERITY_STYLES["INFO"])
        super().__init__(
            master,
            text=f" {severity.upper()} ",
            fg_color=style["bg"],
            text_color=style["fg"],
            font=ctk.CTkFont(size=10, weight="bold"),
            corner_radius=4,
            **kwargs,
        )

    def set_severity(self, severity: str) -> None:
        style = SEVERITY_STYLES.get(severity.upper(), SEVERITY_STYLES["INFO"])
        self.configure(
            text=f" {severity.upper()} ",
            fg_color=style["bg"],
            text_color=style["fg"],
        )
