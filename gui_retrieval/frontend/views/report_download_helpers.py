"""
Frontend helpers for one-step PDF download actions.
"""

from __future__ import annotations

import base64

import streamlit.components.v1 as components


def trigger_pdf_download(file_name: str, payload: bytes, *, key: str) -> None:
    encoded = base64.b64encode(payload).decode("ascii")
    html = f"""
    <html>
      <body style="margin:0;font-family:Segoe UI, Arial, sans-serif;font-size:12px;color:#475569;">
        <a id="{key}" download="{file_name}" href="data:application/pdf;base64,{encoded}">download</a>
        <script>
          const link = document.getElementById("{key}");
          if (link) {{
            link.click();
          }}
        </script>
        <p style="margin:0;">PDF export is ready. If your browser blocks automatic downloads, use the link in this panel.</p>
      </body>
    </html>
    """
    components.html(html, height=42)
