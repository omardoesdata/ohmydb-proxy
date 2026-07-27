"""Native desktop confirmation dialog for policy-controlled SQL queries."""

from __future__ import annotations

import asyncio
import queue
import threading
from dataclasses import dataclass
from typing import Optional

from .confirmation import ConfirmationProvider, QueryContext


@dataclass(frozen=True)
class PopupTheme:
    title: str = "SQL Safety Proxy"
    width: int = 820
    height: int = 690


@dataclass(frozen=True)
class PopupDisplayModel:
    heading: str
    severity: str
    policy_action: str
    operation: str
    database: str
    target_table: str
    estimated_rows: str
    policy_reason: str
    classification_reason: str
    estimate_note: Optional[str]
    sql: str


def build_display_model(ctx: QueryContext) -> PopupDisplayModel:
    decision = ctx.policy_decision

    severity = (
        decision.severity.value
        if decision is not None
        else ctx.classification.severity.value
    )

    policy_action = (
        decision.action.value
        if decision is not None
        else "CONFIRM"
    )

    if ctx.estimated_rows is None:
        estimated_rows = "Unavailable"
    else:
        estimated_rows = f"{ctx.estimated_rows:,}"

        if ctx.approximate_estimate:
            estimated_rows += " (approximate)"

    estimate_note = None

    if ctx.estimate_error:
        estimate_note = ctx.estimate_error

    return PopupDisplayModel(
        heading="Database query requires confirmation",
        severity=severity,
        policy_action=policy_action,
        operation=ctx.classification.statement_type,
        database=ctx.database or "Unknown",
        target_table=ctx.classification.target_table or "Unknown",
        estimated_rows=estimated_rows,
        policy_reason=(
            decision.reason
            if decision is not None
            else "Explicit confirmation is required"
        ),
        classification_reason=ctx.classification.reason,
        estimate_note=estimate_note,
        sql=ctx.sql,
    )


class PopupConfirmationProvider(ConfirmationProvider):
    """Display a serialized native Tkinter confirmation dialog."""

    def __init__(
        self,
        theme: PopupTheme | None = None,
    ) -> None:
        self.theme = theme or PopupTheme()
        self._dialog_lock = threading.Lock()

    async def confirm(self, ctx: QueryContext) -> bool:
        return await asyncio.to_thread(
            self._show_dialog_serialized,
            ctx,
        )

    def _show_dialog_serialized(
        self,
        ctx: QueryContext,
    ) -> bool:
        with self._dialog_lock:
            return self._show_dialog(ctx)

    def _show_dialog(
        self,
        ctx: QueryContext,
    ) -> bool:
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as exc:
            raise RuntimeError(
                "Tkinter is unavailable. Set CONFIRMATION_MODE=cli "
                "or install a Python build containing Tk support."
            ) from exc

        model = build_display_model(ctx)
        result: queue.SimpleQueue[bool] = queue.SimpleQueue()

        root = tk.Tk()
        root.title(
            f"{self.theme.title} - {model.severity} Risk"
        )
        root.geometry(
            f"{self.theme.width}x{self.theme.height}"
        )
        root.minsize(700, 600)
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

        root.protocol(
            "WM_DELETE_WINDOW",
            lambda: finish(False),
        )
        root.bind(
            "<Escape>",
            lambda _event: finish(False),
        )

        outer = ttk.Frame(
            root,
            padding=20,
        )
        outer.pack(
            fill="both",
            expand=True,
        )
        outer.columnconfigure(
            0,
            weight=1,
        )
        outer.rowconfigure(
            6,
            weight=1,
        )

        ttk.Label(
            outer,
            text=model.heading,
            font=("Segoe UI", 18, "bold"),
        ).grid(
            row=0,
            column=0,
            sticky="w",
        )

        ttk.Label(
            outer,
            text=(
                "Review the policy result and estimated impact before "
                "allowing this query to reach the database."
            ),
            wraplength=self.theme.width - 60,
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=(5, 16),
        )

        summary = ttk.LabelFrame(
            outer,
            text="Safety assessment",
            padding=12,
        )
        summary.grid(
            row=2,
            column=0,
            sticky="ew",
        )

        for column in range(4):
            summary.columnconfigure(
                column,
                weight=1,
            )

        self._add_summary_value(
            summary,
            row=0,
            column=0,
            label="Severity",
            value=model.severity,
        )
        self._add_summary_value(
            summary,
            row=0,
            column=1,
            label="Policy action",
            value=model.policy_action,
        )
        self._add_summary_value(
            summary,
            row=0,
            column=2,
            label="Operation",
            value=model.operation,
        )
        self._add_summary_value(
            summary,
            row=0,
            column=3,
            label="Estimated rows",
            value=model.estimated_rows,
        )

        self._add_summary_value(
            summary,
            row=1,
            column=0,
            label="Database",
            value=model.database,
            column_span=2,
        )
        self._add_summary_value(
            summary,
            row=1,
            column=2,
            label="Target table",
            value=model.target_table,
            column_span=2,
        )

        ttk.Label(
            outer,
            text="Policy reason",
            font=("Segoe UI", 10, "bold"),
        ).grid(
            row=3,
            column=0,
            sticky="w",
            pady=(16, 3),
        )

        ttk.Label(
            outer,
            text=model.policy_reason,
            wraplength=self.theme.width - 60,
        ).grid(
            row=4,
            column=0,
            sticky="w",
        )

        classification_text = (
            f"Classifier: {model.classification_reason}"
        )

        if model.estimate_note:
            classification_text += (
                f"\nEstimate note: {model.estimate_note}"
            )

        ttk.Label(
            outer,
            text=classification_text,
            wraplength=self.theme.width - 60,
        ).grid(
            row=5,
            column=0,
            sticky="w",
            pady=(8, 14),
        )

        sql_frame = ttk.LabelFrame(
            outer,
            text="SQL query",
            padding=8,
        )
        sql_frame.grid(
            row=6,
            column=0,
            sticky="nsew",
        )
        sql_frame.columnconfigure(
            0,
            weight=1,
        )
        sql_frame.rowconfigure(
            0,
            weight=1,
        )

        sql_box = tk.Text(
            sql_frame,
            wrap="word",
            height=12,
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )

        scrollbar = ttk.Scrollbar(
            sql_frame,
            orient="vertical",
            command=sql_box.yview,
        )

        sql_box.configure(
            yscrollcommand=scrollbar.set,
        )
        sql_box.grid(
            row=0,
            column=0,
            sticky="nsew",
        )
        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        sql_box.insert(
            "1.0",
            model.sql,
        )
        sql_box.configure(
            state="disabled",
        )

        buttons = ttk.Frame(outer)
        buttons.grid(
            row=7,
            column=0,
            sticky="e",
            pady=(18, 0),
        )

        cancel_button = ttk.Button(
            buttons,
            text="Cancel query",
            command=lambda: finish(False),
        )
        cancel_button.pack(
            side="left",
            padx=(0, 10),
        )

        proceed_button = ttk.Button(
            buttons,
            text="Proceed anyway",
            command=lambda: finish(True),
        )
        proceed_button.pack(
            side="left",
        )

        cancel_button.focus_set()

        # Safe keyboard default: Enter and Escape both cancel.
        root.bind(
            "<Return>",
            lambda _event: finish(False),
        )

        root.transient()
        root.grab_set()
        root.mainloop()

        result.put(approved)
        return result.get()

    @staticmethod
    def _add_summary_value(
        parent,
        row: int,
        column: int,
        label: str,
        value: str,
        column_span: int = 1,
    ) -> None:
        from tkinter import ttk

        frame = ttk.Frame(
            parent,
            padding=(4, 5),
        )
        frame.grid(
            row=row,
            column=column,
            columnspan=column_span,
            sticky="nsew",
        )

        ttk.Label(
            frame,
            text=label,
            font=("Segoe UI", 9),
        ).pack(
            anchor="w",
        )

        ttk.Label(
            frame,
            text=value,
            font=("Segoe UI", 11, "bold"),
            wraplength=300,
        ).pack(
            anchor="w",
        )
