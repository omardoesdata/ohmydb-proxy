"""Native desktop confirmation dialog for risky SQL statements.

Tkinter is part of standard CPython on Windows, so this adds no third-party UI
runtime. The dialog runs in a worker thread because Tk owns a blocking event
loop and the proxy itself runs on asyncio.
"""
from __future__ import annotations

import asyncio
import queue
import threading
from dataclasses import dataclass

from .confirmation import ConfirmationProvider, QueryContext


@dataclass(frozen=True)
class PopupTheme:
    title: str = "SQL Safety Proxy - Risky Query"
    width: int = 760
    height: int = 570


class PopupConfirmationProvider(ConfirmationProvider):
    """Ask for approval using a native Tkinter dialog.

    A fresh Tk root is created for each decision and is kept entirely inside
    one worker thread. This avoids mixing Tk's event loop with asyncio's event
    loop and makes simultaneous client connections safe: dialogs are
    serialized so they do not pile up over one another.
    """

    def __init__(self, theme: PopupTheme | None = None) -> None:
        self.theme = theme or PopupTheme()
        self._dialog_lock = threading.Lock()

    async def confirm(self, ctx: QueryContext) -> bool:
        return await asyncio.to_thread(self._show_dialog_serialized, ctx)

    def _show_dialog_serialized(self, ctx: QueryContext) -> bool:
        with self._dialog_lock:
            return self._show_dialog(ctx)

    def _show_dialog(self, ctx: QueryContext) -> bool:
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as exc:  # pragma: no cover - platform installation issue
            raise RuntimeError(
                "Tkinter is unavailable. Set CONFIRMATION_MODE=cli or install a "
                "Python build that includes Tk support."
            ) from exc

        result: queue.SimpleQueue[bool] = queue.SimpleQueue()
        root = tk.Tk()
        root.title(self.theme.title)
        root.geometry(f"{self.theme.width}x{self.theme.height}")
        root.minsize(620, 470)
        root.attributes("-topmost", True)

        try:
            root.eval("tk::PlaceWindow . center")
        except tk.TclError:
            pass

        approved = False

        def finish(value: bool) -> None:
            nonlocal approved
            approved = value
            try:
                root.grab_release()
            except tk.TclError:
                pass
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        root.bind("<Escape>", lambda _event: finish(False))

        outer = ttk.Frame(root, padding=20)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)

        ttk.Label(
            outer,
            text="Risky database query detected",
            font=("Segoe UI", 17, "bold"),
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            outer,
            text="Review the impact carefully before allowing this query to reach the database.",
            wraplength=self.theme.width - 60,
        ).grid(row=1, column=0, sticky="w", pady=(6, 16))

        impact = (
            f"Estimated rows affected: {ctx.estimated_rows:,}"
            if ctx.estimated_rows is not None
            else "Estimated rows affected: unavailable"
        )
        ttk.Label(outer, text=impact, font=("Segoe UI", 12, "bold")).grid(
            row=2, column=0, sticky="w", pady=(0, 8)
        )

        reason_text = ctx.classification.reason
        if ctx.estimate_error:
            reason_text += f"\nEstimate note: {ctx.estimate_error}"
        ttk.Label(outer, text=reason_text, wraplength=self.theme.width - 60).grid(
            row=3, column=0, sticky="w", pady=(0, 14)
        )

        sql_frame = ttk.LabelFrame(outer, text="SQL query", padding=8)
        sql_frame.grid(row=4, column=0, sticky="nsew")
        sql_frame.columnconfigure(0, weight=1)
        sql_frame.rowconfigure(0, weight=1)

        sql_box = tk.Text(
            sql_frame,
            wrap="word",
            height=12,
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        scrollbar = ttk.Scrollbar(sql_frame, orient="vertical", command=sql_box.yview)
        sql_box.configure(yscrollcommand=scrollbar.set)
        sql_box.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        sql_box.insert("1.0", ctx.sql)
        sql_box.configure(state="disabled")

        buttons = ttk.Frame(outer)
        buttons.grid(row=5, column=0, sticky="e", pady=(18, 0))

        cancel_button = ttk.Button(buttons, text="Cancel query", command=lambda: finish(False))
        cancel_button.pack(side="left", padx=(0, 10))
        proceed_button = ttk.Button(buttons, text="Proceed anyway", command=lambda: finish(True))
        proceed_button.pack(side="left")

        # Safe default: keyboard focus starts on Cancel; Enter therefore blocks.
        cancel_button.focus_set()
        root.bind("<Return>", lambda _event: finish(False))

        root.transient()
        root.grab_set()
        root.mainloop()
        result.put(approved)
        return result.get()
