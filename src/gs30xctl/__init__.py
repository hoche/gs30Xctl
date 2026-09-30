"""
gs30xctl — control NETGEAR GS305E / GS305EP / GS305EPP / GS308E / GS308EP /
GS308EPP "Plus" switches (PoE, 802.1Q VLANs, port PVIDs) over their web UI.

    from gs30xctl import Switch

    with Switch("192.168.1.2", "mypassword") as sw:
        print(sw.model)                       # auto-detected, e.g. GS308EP
        sw.set_dot1q_enabled(True)
        sw.add_vlan(10)
        sw.set_vlan_membership(10, "U,U,N,N,N,N,N,T")
        sw.set_port_pvid(1, 10)
        if sw.model.has_poe:
            sw.poe_cycle([3])
"""

from .client import Switch, encrypt_password
from .exceptions import LoginError, ModelDetectionError, SwitchError, UnsupportedFeatureError
from .models import MODELS, SwitchModel, detect_model_in_html, get_model
from .poe import PoePortSetting, PoePortStatus
from .vlan import (MEMBER_NONE, MEMBER_TAGGED, MEMBER_UNTAGGED, membership_to_labels,
                   normalize_membership)

__version__ = "0.2.0"

# Backwards-compatible name from the original single-file gs305eppctl.py
GS305EPPSwitch = Switch

__all__ = [
    "Switch", "GS305EPPSwitch", "encrypt_password",
    "SwitchError", "LoginError", "ModelDetectionError", "UnsupportedFeatureError",
    "SwitchModel", "MODELS", "get_model", "detect_model_in_html",
    "PoePortStatus", "PoePortSetting",
    "MEMBER_UNTAGGED", "MEMBER_TAGGED", "MEMBER_NONE",
    "normalize_membership", "membership_to_labels",
]
