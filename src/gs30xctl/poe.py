"""PoE value mappings, data classes and page parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from . import _html

# Value mappings (from the switch's web UI <select>/<input> encodings)
PWR_MODE = {"0": "802.3af", "1": "legacy", "2": "pre-802.3at", "3": "802.3at"}
PORT_PRIO = {"0": "low", "2": "high", "3": "critical"}
LIMIT_TYPE = {"0": "none", "1": "class", "2": "user"}
DETEC_TYPE = {"1": "Legacy", "2": "IEEE 802", "3": "4pt 802.3af + Legacy"}
LONGER_DETECT = {"0": "Get Value Fault", "2": "disable", "3": "enable"}


def code_for(mapping: Dict[str, str], value: str, default: str = "") -> str:
    """Look up the code for a human-readable value (or a raw code) in a code->label map."""
    value = value.strip().lower()
    for k, v in mapping.items():
        if v.lower() == value or k == value:
            return k
    return default


@dataclass
class PoePortStatus:
    port: int
    status: str            # e.g. "Delivering Power" / "Disabled" / "Searching"
    power_class: str
    voltage_v: float
    current_ma: float
    power_w: float
    temperature_c: float
    error_status: str

    def __str__(self):
        return (f"Port {self.port}: {self.status:<20s} "
                f"{self.power_w:5.2f}W  {self.voltage_v:5.1f}V  "
                f"{self.current_ma:6.1f}mA  {self.temperature_c:4.1f}C"
                f"{'  ERR=' + self.error_status if self.error_status else ''}")


@dataclass
class PoePortSetting:
    port: int
    name: str
    power_enabled: bool
    power_mode: str
    priority: str
    limit_type: str
    power_limit: str
    detect_type: str
    longer_detect: str

    def __str__(self):
        state = "enabled" if self.power_enabled else "disabled"
        return (f"Port {self.port}: power={state:<8s} mode={self.power_mode:<11s} "
                f"prio={self.priority:<8s} limit_type={self.limit_type:<5s} "
                f"limit={self.power_limit}W detect={self.detect_type}")


def _port_number(chunk: str, fallback: int) -> int:
    try:
        return int(_html.hidden_value(chunk, "port", by="class"))
    except ValueError:
        return fallback


def parse_poe_status(html: str) -> List[PoePortStatus]:
    """Parse getPoePortStatus.cgi."""
    result = []
    for i, chunk in enumerate(_html.li_blocks(html, "poePortStatusListItem"), start=1):
        status_texts = _html.span_texts(chunk, "poe-power-mode")
        class_texts = _html.span_texts(chunk, "poe-portPwr-width")

        # div.poe_port_status div div span sequence:
        # [0]=label 'Voltage', [1]=value, [2]=label 'Current', [3]=value, ...
        m = re.search(r'<div\b[^>]*class=["\']poe_port_status["\'][^>]*>(.*?)</div>\s*(?:</div>)?$',
                      chunk, re.DOTALL | re.IGNORECASE)
        spans = _html.spans_in_order(m.group(1) if m else chunk)

        def value(idx: int) -> float:
            return _html.num(spans[idx]) if len(spans) > idx else 0.0

        result.append(PoePortStatus(
            port=_port_number(chunk, i),
            status=status_texts[0] if status_texts else "",
            power_class=class_texts[0] if class_texts else "",
            voltage_v=value(1), current_ma=value(3), power_w=value(5),
            temperature_c=value(7),
            error_status=spans[9].strip() if len(spans) > 9 else "",
        ))
    return result


def parse_poe_settings(html: str) -> List[PoePortSetting]:
    """Parse PoEPortConfig.cgi."""
    result = []
    for i, chunk in enumerate(_html.li_blocks(html, "poePortSettingListItem"), start=1):
        hv = _html.hidden_value
        mode = hv(chunk, "hidPwrMode", by="id")
        prio = hv(chunk, "hidPortPrio", by="id")
        limit_type = hv(chunk, "hidLimitType", by="id")
        detect = hv(chunk, "hidDetecType", by="id")
        longer = hv(chunk, "longerDetect", by="class")
        result.append(PoePortSetting(
            port=_port_number(chunk, i),
            name=hv(chunk, "portName", by="class"),
            power_enabled=(hv(chunk, "hidPortPwr", by="id") == "1"),
            power_mode=PWR_MODE.get(mode, mode),
            priority=PORT_PRIO.get(prio, prio),
            limit_type=LIMIT_TYPE.get(limit_type, limit_type),
            power_limit=hv(chunk, "pwrLimit", by="class"),
            detect_type=DETEC_TYPE.get(detect, detect),
            longer_detect=LONGER_DETECT.get(longer, longer),
        ))
    return result
