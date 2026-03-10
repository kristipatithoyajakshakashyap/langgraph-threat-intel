"""
Main Application Class - OOP Design
"""

import streamlit as st
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services import SessionManager, APIClient
from components import SidebarComponent, QueryInputComponent, ResultsComponent


class ThreatIntelApp:
    """Main application class for the Threat Intelligence Agent."""

    def __init__(self):
        st.set_page_config(
            page_title="Threat Intelligence Agent",
            page_icon="A",
            layout="wide",
            initial_sidebar_state="expanded",
        )

        self.session = SessionManager()
        self.api = APIClient()

        self.sidebar = SidebarComponent(self.api)
        self.query_input = QueryInputComponent()
        self.results = ResultsComponent()

        self.session.init()

    def run(self):
        self._render_header()
        current = self.session.get("query_result")
        current_id = current.get("investigation_id") if current else None
        self.sidebar.render(
            selected_investigation_id=current_id,
            on_history_click=self._on_history_click,
            on_delete_click=self._on_delete_click,
        )

        example = self.session.get("example_clicked")
        if example:
            self.session.set("example_clicked", None)
            self._handle_investigation(example)

        submit_btn, query = self.query_input.render(
            on_submit=self._handle_investigation,
            on_example_click=self._on_example_click,
        )

        if submit_btn and query:
            self._handle_investigation(query)

        result = self.session.get("query_result")
        if result:
            self.results.render(result)
            self._render_export_buttons(result)

    def _render_header(self):
        st.title("Threat Intelligence Agent")
        st.markdown("*AI-Powered Threat Investigation System*")

    def _handle_investigation(self, query: str):
        if not query:
            return

        self.session.set("query_result", None)

        investigation_id = self.api.submit_investigation(query)

        if investigation_id:
            with st.spinner("Analyzing threat indicators..."):
                time.sleep(3)

                result = self.api.get_investigation(investigation_id)

                if result:
                    self.session.set("query_result", result)
                    st.rerun()
        else:
            st.error(
                "Failed to submit investigation. Please check if the API is running."
            )

    def _on_example_click(self, example: str):
        self.session.set("example_clicked", example)

    def _on_history_click(self, investigation_id: str):
        result = self.api.get_investigation(investigation_id)
        if result:
            self.session.set("query_result", result)
            st.rerun()

    def _on_delete_click(self, investigation_id: str):
        deleted = self.api.delete_investigation(investigation_id)
        if deleted:
            current = self.session.get("query_result")
            if current and current.get("investigation_id") == investigation_id:
                self.session.set("query_result", None)
            st.success(f"Deleted chat: {investigation_id}")
            st.rerun()
        else:
            st.error("Unable to delete selected chat.")

    def _render_export_buttons(self, result: dict):
        col1, col2 = st.columns(2)

        with col1:
            md_content = ResultsComponent.export_markdown(result)
            st.download_button(
                label="Export as Markdown",
                data=md_content,
                file_name=f"threat_report_{result.get('investigation_id', 'unknown')}.md",
                mime="text/markdown",
                use_container_width=True,
            )

        with col2:
            pdf_bytes = ResultsComponent.export_pdf_bytes(result)
            st.download_button(
                label="Export as PDF",
                data=pdf_bytes,
                file_name=f"threat_report_{result.get('investigation_id', 'unknown')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )


def main():
    app = ThreatIntelApp()
    app.run()


if __name__ == "__main__":
    main()
