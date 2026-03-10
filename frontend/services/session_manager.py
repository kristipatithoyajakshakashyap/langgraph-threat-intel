from typing import Any

import streamlit as st


class SessionManager:
    @staticmethod
    def init() -> None:
        defaults = {
            "query_result": None,
            "example_clicked": None,
            "is_investigating": False,
        }
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        return st.session_state.get(key, default)

    @staticmethod
    def set(key: str, value: Any) -> None:
        st.session_state[key] = value
