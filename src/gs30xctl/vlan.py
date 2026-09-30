"""802.1Q VLAN membership encoding helpers."""

from __future__ import annotations

import re
from typing import List

# One character per port in the switch's "hiddenMem" field
MEMBER_UNTAGGED = "1"
MEMBER_TAGGED = "2"
MEMBER_NONE = "3"

_ALIASES = {
    "u": MEMBER_UNTAGGED, "untagged": MEMBER_UNTAGGED,
    "t": MEMBER_TAGGED, "tagged": MEMBER_TAGGED,
    "n": MEMBER_NONE, "none": MEMBER_NONE, "-": MEMBER_NONE, "0": MEMBER_NONE,
}


def normalize_membership(spec) -> str:
    """
    Convert a friendly membership spec into the switch's internal encoding.

    Accepts:
      - a raw string like "12331" (already using 1/2/3)
      - a comma/space separated string like "U,U,N,N,T" or "untagged untagged none none tagged"
      - a list of strings/chars, e.g. ["U", "U", "N", "N", "T"]
    """
    if isinstance(spec, (list, tuple)):
        tokens = list(spec)
    else:
        s = str(spec).strip()
        if re.fullmatch(r"[123]+", s):
            return s
        tokens = re.split(r"[,\s]+", s)

    out = []
    for t in tokens:
        t = str(t).strip()
        if t in ("1", "2", "3"):
            out.append(t)
        elif t.lower() in _ALIASES:
            out.append(_ALIASES[t.lower()])
        else:
            raise ValueError(f"Unrecognized membership token: {t!r}")
    return "".join(out)


def membership_to_labels(membership: str) -> List[str]:
    labels = {MEMBER_UNTAGGED: "untagged", MEMBER_TAGGED: "tagged", MEMBER_NONE: "none"}
    return [labels.get(c, "?") for c in membership]
