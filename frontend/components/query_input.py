from typing import Callable, Tuple

import streamlit as st


class QueryInputComponent:
    EXAMPLES = [
        "1.1.1.1",
        "8.8.8.8",
        "evil.com",
        "https://malware.test/payload",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]

    def render(
        self,
        on_submit: Callable[[str], None],
        on_example_click: Callable[[str], None],
    ) -> Tuple[bool, str]:
        st.markdown("### Investigate Threat Indicators")
        st.caption("Enter IP, domain, URL, or file hash. Example: 1.1.1.1 or evil.com")

        col1, col2 = st.columns([4, 1])
        with col1:
            query = st.text_input(
                "query",
                placeholder="e.g., 1.1.1.1, evil.com, https://malware.test/payload",
                help="Threat query to investigate",
                label_visibility="collapsed",
                key="query_input",
            )
        with col2:
            st.write("")
            investigate = st.button(
                "Investigate", use_container_width=True, type="primary"
            )

        st.caption("Quick examples")
        cols = st.columns(len(self.EXAMPLES))
        for idx, example in enumerate(self.EXAMPLES):
            with cols[idx]:
                if st.button(example, key=f"example_{idx}", use_container_width=True):
                    on_example_click(example)

        return investigate, query
