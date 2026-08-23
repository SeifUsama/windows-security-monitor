"""
app/ui/widgets/stat_card.py
----------------------------
Reusable statistic card widget for the dashboard.
Displays a label, large numeric value, and optional subtitle.
"""

import customtkinter as ctk


# Color palette
SEVERITY_COLORS = {
    "default":  ("#1a1a2e", "#e0e0e0"),   # (bg, fg)
    "danger":   ("#3d0000", "#ff6b6b"),
    "warning":  ("#3d2b00", "#ffa94d"),
    "success":  ("#003d1a", "#69db7c"),
    "info":     ("#002b3d", "#74c0fc"),
}


class StatCard(ctk.CTkFrame):
    """
    A card that displays:
      - A title (e.g. "Failed Logins")
      - A large numeric value
      - An optional subtitle (e.g. "last 24h")
      - An optional icon character (Unicode)
    
    Color variants: default, danger, warning, success, info
    """

    def __init__(
        self,
        master,
        title: str,
        value: str = "0",
        subtitle: str = "",
        icon: str = "",
        color: str = "default",
        **kwargs,
    ):
        bg, fg = SEVERITY_COLORS.get(color, SEVERITY_COLORS["default"])
        super().__init__(master, fg_color=bg, corner_radius=10, **kwargs)

        self._value_var = ctk.StringVar(value=value)

        # Icon + title row
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=12, pady=(10, 0))

        if icon:
            ctk.CTkLabel(
                top_frame, text=icon, font=ctk.CTkFont(size=16),
                text_color=fg, fg_color="transparent",
            ).pack(side="left")

        ctk.CTkLabel(
            top_frame,
            text=title,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=fg,
            fg_color="transparent",
        ).pack(side="left", padx=(4, 0))

        # Big value
        self._value_label = ctk.CTkLabel(
            self,
            textvariable=self._value_var,
            font=ctk.CTkFont(size=34, weight="bold"),
            text_color=fg,
            fg_color="transparent",
        )
        self._value_label.pack(pady=(2, 0))

        # Subtitle
        if subtitle:
            ctk.CTkLabel(
                self,
                text=subtitle,
                font=ctk.CTkFont(size=9),
                text_color=fg,
                fg_color="transparent",
            ).pack(pady=(0, 8))
        else:
            ctk.CTkLabel(self, text="", height=8, fg_color="transparent").pack()

    def set_value(self, value: str) -> None:
        """Update the displayed value."""
        self._value_var.set(str(value))
