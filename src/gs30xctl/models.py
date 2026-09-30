"""
Hardware model registry for the NETGEAR GS305E / GS308E "Plus" family.

All six models share the same web UI firmware family (``login.cgi`` with an
MD5 "merged" password hash, ``SID`` session cookie, ``8021qCf.cgi`` /
``8021qMembe.cgi`` / ``portPVID.cgi`` for VLANs). They differ only in port
count and whether / on which ports they provide PoE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union


@dataclass(frozen=True)
class SwitchModel:
    name: str
    port_count: int
    poe_ports: Tuple[int, ...] = ()   # 1-based physical port numbers with PoE
    poe_budget_w: float = 0.0

    @property
    def has_poe(self) -> bool:
        return bool(self.poe_ports)

    @property
    def ports(self) -> Tuple[int, ...]:
        return tuple(range(1, self.port_count + 1))

    def __str__(self):
        poe = (f", PoE on ports {self.poe_ports[0]}-{self.poe_ports[-1]} "
               f"({self.poe_budget_w:g}W budget)") if self.has_poe else ", no PoE"
        return f"{self.name} ({self.port_count} ports{poe})"


MODELS: Dict[str, SwitchModel] = {m.name: m for m in (
    SwitchModel("GS305E", 5),
    SwitchModel("GS305EP", 5, poe_ports=(1, 2, 3, 4), poe_budget_w=63),
    SwitchModel("GS305EPP", 5, poe_ports=(1, 2, 3, 4), poe_budget_w=120),
    SwitchModel("GS308E", 8),
    SwitchModel("GS308EP", 8, poe_ports=tuple(range(1, 9)), poe_budget_w=62),
    SwitchModel("GS308EPP", 8, poe_ports=tuple(range(1, 9)), poe_budget_w=123),
)}

# Longest suffix wins because (?:PP?)? is greedy and must end on a word boundary.
_MODEL_RE = re.compile(r"\b(GS30[58]E(?:PP?)?)\b", re.IGNORECASE)


def get_model(model: Union[str, SwitchModel]) -> SwitchModel:
    """Look up a model by name (case-insensitive), or pass a SwitchModel through."""
    if isinstance(model, SwitchModel):
        return model
    key = model.strip().upper()
    try:
        return MODELS[key]
    except KeyError:
        raise ValueError(
            f"Unknown model {model!r}; supported: {', '.join(MODELS)}") from None


def detect_model_in_html(html: str) -> Optional[SwitchModel]:
    """
    Find a supported model name in a page, preferring the <title> tag (the
    login page title is e.g. "NETGEAR GS308EP") over the rest of the body.
    """
    title = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    for text in ((title.group(1) if title else ""), html or ""):
        m = _MODEL_RE.search(text)
        if m:
            return MODELS[m.group(1).upper()]
    return None
