"""HTML parsing helpers (regex-based; no bs4 dependency required)."""

from __future__ import annotations

import re
from typing import List, Tuple


def find_hash(html: str) -> str:
    m = re.search(r'id=[\'"]hash[\'"][^>]*value=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
    if not m:
        m = re.search(r'name=[\'"]hash[\'"][^>]*value=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
    return m.group(1) if m else ""


def hidden_value(html_chunk: str, id_or_class: str, by="id") -> str:
    attr = "id" if by == "id" else "class"
    m = re.search(
        rf'<input\b[^>]*\btype=["\']?hidden["\']?[^>]*\b{attr}=["\']?{re.escape(id_or_class)}["\']?[^>]*\bvalue=["\']([^"\']*)["\']',
        html_chunk, re.IGNORECASE)
    if m:
        return m.group(1)
    # attribute order can vary (value before id/class)
    m = re.search(
        rf'<input\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\b{attr}=["\']?{re.escape(id_or_class)}["\']?',
        html_chunk, re.IGNORECASE)
    return m.group(1) if m else ""


def input_value(html: str, name: str) -> str:
    """Value of the <input name=...> with the given name ('' if absent)."""
    for tag in re.findall(r'<input\b[^>]*>', html, re.IGNORECASE):
        if re.search(rf'\bname=["\']?{re.escape(name)}["\'\s/>]', tag, re.IGNORECASE):
            m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            return m.group(1) if m else ""
    return ""


def select_options(html: str, name: str) -> List[Tuple[str, str, bool]]:
    """(value, label, selected) for each <option> of the <select name=...>."""
    m = re.search(rf'<select\b[^>]*\bname=["\']?{re.escape(name)}["\']?[^>]*>(.*?)</select>',
                  html, re.IGNORECASE | re.DOTALL)
    if not m:
        return []
    out = []
    for attrs, label in re.findall(r'<option\b([^>]*)>(.*?)(?=<option\b|$)', m.group(1),
                                   re.IGNORECASE | re.DOTALL):
        v = re.search(r'\bvalue=["\']?([^"\'\s>]*)', attrs, re.IGNORECASE)
        label = strip_tags(re.sub(r'</option>.*', '', label, flags=re.IGNORECASE | re.DOTALL))
        out.append((v.group(1) if v else label, label, bool(re.search(r'\bselected\b', attrs, re.I))))
    return out


def li_blocks(html: str, css_class: str) -> List[str]:
    """Split out <li ... class="...css_class...">...</li> chunks."""
    pattern = re.compile(
        rf'<li\b[^>]*\bclass=["\'][^"\']*\b{re.escape(css_class)}\b[^"\']*["\'][^>]*>(.*?)</li>',
        re.IGNORECASE | re.DOTALL)
    return pattern.findall(html)


def num(text: str, cast=float, default=0.0):
    m = re.search(r"[-+]?\d*\.?\d+", text or "")
    try:
        return cast(m.group(0)) if m else default
    except (TypeError, ValueError):
        return default


def span_texts(chunk: str, css_class: str) -> List[str]:
    """Text of all <span> elements whose class attribute contains css_class."""
    pattern = re.compile(
        rf'<span\b[^>]*\bclass=["\'][^"\']*\b{re.escape(css_class)}\b[^"\']*["\'][^>]*>(.*?)</span>',
        re.IGNORECASE | re.DOTALL)
    return [strip_tags(t) for t in pattern.findall(chunk)]


def spans_in_order(chunk: str) -> List[str]:
    """All <span>text</span> within (used for the poe_port_status value list)."""
    pattern = re.compile(r'<span\b[^>]*>(.*?)</span>', re.IGNORECASE | re.DOTALL)
    return [strip_tags(t) for t in pattern.findall(chunk)]


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html).strip()
