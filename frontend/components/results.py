from io import BytesIO
from typing import Any, Dict, Optional

import streamlit as st


class ResultsComponent:
    def render(self, result: Optional[Dict[str, Any]]) -> None:
        if not result:
            return

        st.markdown("---")
        st.subheader("Investigation Results")

        self._top_metrics(result)
        st.markdown("---")
        st.subheader("Threat Explanation")
        st.markdown(result.get("threat_explanation", "No explanation available"))
        st.markdown("---")
        st.subheader("How to Resolve")
        st.markdown(result.get("resolution_steps", "No resolution steps available"))

    def _top_metrics(self, result: Dict[str, Any]) -> None:
        risk = float(result.get("risk_score", 0) or 0)
        conf = float(result.get("confidence", 0) or 0)
        indicators = len(result.get("indicators", []))
        status = str(result.get("status", "unknown"))
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk", f"{risk:.1f}")
        c2.metric("Confidence", f"{conf * 100:.0f}%")
        c3.metric("Indicators", indicators)
        c4.metric("Status", status)

    @staticmethod
    def export_markdown(result: Dict[str, Any]) -> str:
        lines = [
            "# Threat Intelligence Report",
            f"- Investigation ID: {result.get('investigation_id', 'N/A')}",
            f"- Risk Score: {result.get('risk_score', 0)}",
            f"- Confidence: {float(result.get('confidence', 0) or 0) * 100:.0f}%",
            "",
            "## Threat Explanation",
            result.get("threat_explanation", ""),
            "",
            "## Resolution Steps",
            result.get("resolution_steps", ""),
            "",
            "## AI Analysis",
            result.get("gemini_analysis", ""),
        ]
        return "\n".join(lines)

    @staticmethod
    def export_pdf_bytes(result: Dict[str, Any]) -> bytes:
        text = ResultsComponent.export_markdown(result)
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            buffer = BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=A4)
            width, height = A4
            x, y = 40, height - 40
            pdf.setFont("Helvetica", 10)
            for raw in text.splitlines():
                line = raw.encode("ascii", "replace").decode("ascii")
                pdf.drawString(x, y, line[:120])
                y -= 12
                if y < 50:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 10)
                    y = height - 40
            pdf.save()
            buffer.seek(0)
            return buffer.read()
        except Exception:
            return b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
