from typing import Callable, Optional

import streamlit as st


class SidebarComponent:
    def __init__(self, api_client):
        self.api_client = api_client

    def render(
        self,
        selected_investigation_id: Optional[str],
        on_history_click: Optional[Callable[[str], None]],
        on_delete_click: Optional[Callable[[str], None]],
    ) -> None:
        with st.sidebar:
            st.title("Threat Intel")
            st.markdown("---")
            self._render_stats(selected_investigation_id)
            st.markdown("---")
            self._render_chats(
                selected_investigation_id, on_history_click, on_delete_click
            )
            st.markdown("---")
            status = "Connected" if self.api_client.check_status() else "Disconnected"
            st.caption(f"API: {status}")

    def _render_stats(self, selected_investigation_id: Optional[str]) -> None:
        st.subheader("Chat Stats")
        if not selected_investigation_id:
            st.info("Run/open a chat to view stats")
            return

        stats = self.api_client.get_investigation_stats(selected_investigation_id)
        if not stats:
            st.warning("Stats unavailable")
            return

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Risk", f"{stats.avg_risk_score:.1f}")
            st.metric("Indicators", stats.indicator_count)
        with col2:
            st.metric("Confidence", f"{stats.confidence * 100:.0f}%")
            st.metric("Sources", stats.source_count)
        st.caption(f"Status: {stats.status}")

    def _render_chats(
        self,
        selected_investigation_id: Optional[str],
        on_history_click: Optional[Callable[[str], None]],
        on_delete_click: Optional[Callable[[str], None]],
    ) -> None:
        st.subheader("Chats")
        investigations = self.api_client.get_investigations(limit=50)
        options = [
            inv.get("investigation_id")
            for inv in investigations
            if inv.get("investigation_id")
        ]
        if not options:
            st.info("No chats yet")
            return

        labels = {}
        for inv in investigations:
            inv_id = inv.get("investigation_id")
            if not inv_id:
                continue
            risk = float(inv.get("risk_score", 0) or 0)
            labels[inv_id] = f"{inv_id} ({risk:.0f}%)"

        idx = (
            options.index(selected_investigation_id)
            if selected_investigation_id in options
            else 0
        )
        selected = st.selectbox(
            "Select chat",
            options,
            index=idx,
            format_func=lambda x: labels.get(x, x),
            key="chat_selector",
        )

        c1, c2 = st.columns(2)
        with c1:
            if (
                st.button("Open", use_container_width=True, key="open_chat")
                and on_history_click
            ):
                on_history_click(selected)
        with c2:
            if (
                st.button("Delete", use_container_width=True, key="delete_chat")
                and on_delete_click
            ):
                on_delete_click(selected)
