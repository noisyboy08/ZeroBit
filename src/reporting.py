"""
PDF reporting for ZeroBit using fpdf.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd
from fpdf import FPDF  # type: ignore


class SecurityReport(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "ZeroBit Security Audit", ln=1, align="C")
        self.ln(5)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Generated: {datetime.utcnow().isoformat()}Z", 0, 0, "C")

    def generate_daily_report(self, alerts_df: pd.DataFrame, output_path: str) -> str:
        """
        Build a simple PDF with summary and alert rows.
        """
        self.add_page()

        # Executive Summary
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "Executive Summary", ln=1)
        self.set_font("Helvetica", "", 11)
        total = len(alerts_df) if alerts_df is not None else 0
        self.cell(0, 10, f"Total Incidents: {total}", ln=1)
        self.ln(5)

        if alerts_df is None or alerts_df.empty:
            self.set_font("Helvetica", "I", 10)
            self.cell(0, 10, "No alerts recorded.", ln=1)
            self.output(output_path)
            return output_path

        # Table header
        self.set_font("Helvetica", "B", 11)
        self.cell(60, 8, "Time", border=1)
        self.cell(60, 8, "IP", border=1)
        self.cell(60, 8, "Type", border=1, ln=1)

        # Rows
        self.set_font("Helvetica", "", 10)
        for _, row in alerts_df.iterrows():
            time_val = str(row.get("timestamp", ""))
            ip_val = str(row.get("src_ip", ""))
            type_val = str(row.get("label", row.get("type", "Malicious")))
            self.cell(60, 8, time_val[:30], border=1)
            self.cell(60, 8, ip_val[:30], border=1)
            self.cell(60, 8, type_val[:30], border=1, ln=1)

        self.output(output_path)
        return output_path

