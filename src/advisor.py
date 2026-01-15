"""
Generative AI advisor for remediation guidance using Groq LLM.
"""

from __future__ import annotations

import os
from typing import Optional

from groq import Groq  # type: ignore


class SecurityAdvisor:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY is required (env or parameter).")
        self.client = Groq(api_key=self.api_key)

    def get_remediation(
        self,
        attack_type: str,
        ip_address: str,
        affected_port: str,
        os_system: str,
    ) -> str:
        prompt = (
            "You are a CyberSecurity Expert. "
            f"A {attack_type} attack was detected from IP {ip_address} targeting port {affected_port} "
            f"on a {os_system} machine. Provide a 2-sentence summary of what is happening, "
            "and then provide the EXACT terminal command to block this specific threat."
        )
        resp = self.client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=256,
        )
        return resp.choices[0].message.content

