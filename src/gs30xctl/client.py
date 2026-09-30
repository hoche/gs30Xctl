"""
HTTP client for NETGEAR GS305E / GS305EP / GS305EPP / GS308E / GS308EP /
GS308EPP "Plus" switches.

These switches have no SSH/CLI/REST API — everything goes through the web UI,
which this module talks to directly over HTTP. Protocol details (login
hashing, form field names, endpoints) were reverse engineered from the
open-source `ntgrrc` / `go-netgear` and `netgear-tool` projects.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Union

import requests

from . import _html
from .exceptions import LoginError, ModelDetectionError, SwitchError, UnsupportedFeatureError
from .models import SwitchModel, detect_model_in_html, get_model
from .poe import (DETEC_TYPE, LIMIT_TYPE, LONGER_DETECT, PORT_PRIO, PWR_MODE,
                  PoePortSetting, PoePortStatus, code_for, parse_poe_settings,
                  parse_poe_status)
from .vlan import MEMBER_NONE, normalize_membership

log = logging.getLogger(__name__)

# Older GS108Ev3-derived firmware names the session cookie GS108SID.
_COOKIE_RE = re.compile(r"\b((?:GS108)?SID)=([^;]+)")


@dataclass(frozen=True)
class IpSettings:
    """Management IP configuration from switch_info.cgi."""
    dhcp: bool
    ip: str
    netmask: str
    gateway: str


def _special_merge(password: str, seed: str) -> str:
    """Interleave password and seed characters (Netgear login.js algorithm)."""
    out = []
    for i in range(max(len(password), len(seed))):
        if i < len(password):
            out.append(password[i])
        if i < len(seed):
            out.append(seed[i])
    return "".join(out)


def encrypt_password(password: str, seed: str) -> str:
    return hashlib.md5(_special_merge(password, seed).encode()).hexdigest()


class Switch:
    """
    Controller for a NETGEAR GS305E/GS308E-family switch.

    The model is auto-detected from the login page unless given explicitly.
    PoE methods raise UnsupportedFeatureError on non-PoE models.

    Usage:
        with Switch("192.168.1.2", "password") as sw:
            print(sw.model)
            sw.add_vlan(10)
            if sw.model.has_poe:
                sw.poe_port_off(3)
    """

    def __init__(self, host: str, password: Optional[str] = None, *,
                 model: Union[str, SwitchModel, None] = None,
                 timeout: float = 10.0,
                 password_provider: Optional[Callable[[], str]] = None,
                 session: Optional[requests.Session] = None):
        """
        `password` may be omitted if `password_provider` is given instead —
        a zero-arg callable invoked lazily, only if a real login attempt
        turns out to be necessary (e.g. because there's no valid cached
        session). This avoids prompting for a password when a cached
        session token still works.
        """
        self.host = host
        self._password = password
        self._password_provider = password_provider
        self._model: Optional[SwitchModel] = get_model(model) if model else None
        self.timeout = timeout
        self._session = session or requests.Session()
        # Some firmware checks the Referer header to distinguish in-app
        # requests from direct navigation, and silently ignores logout.cgi
        # (and possibly other) requests without it — leaving a stale session
        # occupying the switch's single session slot.
        # NOTE: Referer must match the page a request "came from" or the CSRF
        # hash check on write endpoints (e.g. PoEPortConfig.cgi) fails with
        # "CHECK HASH FAILED" — even though the change had already been
        # applied. So we don't pin one Referer for every request; login() sets
        # it to login.cgi for the login POST specifically, and it's left
        # pointing at index.cgi (a generic authenticated page) otherwise.
        self._session.headers.update({
            "Referer": self._url("index.cgi"),
            "Origin": f"http://{self.host}",
        })
        self._sid: Optional[str] = None
        self._cookie_name = "SID"
        self._login_time = 0.0
        self._session_ttl = 270.0  # switch drops idle sessions after ~5 min

    # -- properties --------------------------------------------------------

    @property
    def password(self) -> str:
        if self._password is None:
            if self._password_provider is None:
                raise LoginError(
                    "No password available: pass password=... or password_provider=... to Switch()")
            self._password = self._password_provider()
        return self._password

    @property
    def model(self) -> SwitchModel:
        """The switch's hardware model, detected on first access if not given."""
        if self._model is None:
            self._model = self.detect_model()
        return self._model

    @property
    def port_count(self) -> int:
        return self.model.port_count

    @property
    def session_id(self) -> Optional[str]:
        """The current session token, if logged in (useful for caching/reuse)."""
        return self._sid

    def adopt_session(self, sid: str):
        """
        Reuse a previously-obtained SID instead of performing a fresh login.
        If it turns out to be stale/invalid, the next request transparently
        falls back to a real login (this requires a password or
        password_provider to have been set).
        """
        self._sid = sid
        self._login_time = time.time()

    # -- low level ---------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"http://{self.host}/{path.lstrip('/')}"

    def _headers(self) -> Dict[str, str]:
        return {"Cookie": f"{self._cookie_name}={self._sid}"} if self._sid else {}

    @staticmethod
    def _looks_like_login_page(text: str) -> bool:
        # NOTE: don't use a generic "short body" heuristic here — legitimate
        # write responses like "SUCCESS" (7 chars) would be misidentified as
        # an invalid session, triggering a pointless (and disruptive)
        # re-login right after a write that had already succeeded.
        if not text:
            return True
        lower = text.lower()
        return ("login.cgi" in lower and "id='rand'" in lower) or "Redirect to Login" in text

    def _ensure_session(self):
        if not self._sid or (time.time() - self._login_time > self._session_ttl):
            self.login()

    def _request(self, method: str, path: str, data=None) -> str:
        self._ensure_session()
        for attempt in (1, 2):
            r = self._session.request(method, self._url(path), data=data,
                                      headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            log.debug("%s /%s -> %s len=%d", method, path, r.status_code, len(r.text))
            if attempt == 1 and self._looks_like_login_page(r.text):
                log.debug("session rejected; logging in again")
                self.login()
                continue
            return r.text

    def _get(self, path: str) -> str:
        return self._request("GET", path)

    def _post(self, path: str, data) -> str:
        return self._request("POST", path, data)

    # -- session -----------------------------------------------------------

    def login(self, retries: int = 3, retry_delay: float = 2.5):
        """
        Authenticate with the switch.

        Some firmware briefly rejects new logins (no SID cookie returned)
        after several rapid successive login attempts, apparently as a simple
        anti-brute-force throttle. If an attempt fails this way, retry a
        couple of times with a short delay before giving up.
        """
        last_error: Optional[SwitchError] = None
        for attempt in range(1, retries + 1):
            try:
                self._login_once()
                return
            except LoginError as e:
                last_error = e
                if attempt < retries:
                    log.debug("login attempt %d/%d failed (%s); retrying in %ss",
                              attempt, retries, e, retry_delay)
                    time.sleep(retry_delay)
        raise last_error

    def _login_once(self):
        r = self._session.get(self._url("login.cgi"), timeout=self.timeout)
        r.raise_for_status()
        log.debug("GET /login.cgi -> %s len=%d headers=%s", r.status_code, len(r.text), dict(r.headers))
        if self._model is None:
            self._model = detect_model_in_html(r.text)
            log.debug("model from login page: %s", self._model)

        m = (re.search(r"id=['\"]rand['\"][^>]*value=['\"](\d+)['\"]", r.text)
             or re.search(r"value=['\"](\d+)['\"][^>]*id=['\"]rand['\"]", r.text))
        if m:
            seed = m.group(1)
        elif r.headers.get("rand"):
            seed = r.headers["rand"]
        else:
            log.debug("login.cgi body snippet: %s", r.text[:1000])
            raise SwitchError(
                "Could not find login seed ('rand') value; unexpected page. "
                "Is this a GS305E/GS308E-family switch? Enable debug logging to see the raw response.")

        encrypted = encrypt_password(self.password, seed)
        # Match the real browser's login request: Referer pointing at
        # login.cgi itself. The session-wide Referer stays at index.cgi.
        r2 = self._session.post(
            self._url("login.cgi"),
            data={"password": encrypted},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": self._url("login.cgi"),
            },
            timeout=self.timeout,
        )
        r2.raise_for_status()
        log.debug("POST /login.cgi -> %s headers=%s", r2.status_code, dict(r2.headers))

        m = _COOKIE_RE.search(r2.headers.get("Set-Cookie", ""))
        if not m:
            err_m = re.search(r'id=["\']pwdErr["\'][^>]*>(.*?)</div>', r2.text, re.DOTALL)
            detail = _html.strip_tags(err_m.group(1)) if err_m else ""
            log.debug("login.cgi POST body snippet: %s", r2.text[:1000])
            msg = ("Login failed: no session cookie returned. Wrong password, or the switch "
                   "already has an active session (only one session is allowed at a time; "
                   "log out of any open browser tab or wait ~5 minutes).")
            if detail:
                msg += f" Switch says: {detail!r}"
            raise LoginError(msg)
        self._cookie_name, self._sid = m.group(1), m.group(2)
        self._login_time = time.time()
        log.debug("%s acquired", self._cookie_name)

    def logout(self):
        if self._sid:
            try:
                r = self._session.get(self._url("logout.cgi"), headers=self._headers(),
                                      timeout=self.timeout)
                log.debug("GET /logout.cgi -> %s", r.status_code)
            except requests.RequestException as e:
                log.debug("logout.cgi request failed: %s", e)
        self._sid = None

    def __enter__(self) -> "Switch":
        self.login()
        return self

    def __exit__(self, *_exc):
        self.logout()

    # -- model detection ---------------------------------------------------

    def detect_model(self) -> SwitchModel:
        """
        Identify the hardware model: first from the (unauthenticated) login
        page title, then from authenticated info pages.
        """
        r = self._session.get(self._url("login.cgi"), timeout=self.timeout)
        found = detect_model_in_html(r.text) if r.ok else None
        for page in ("switch_info.cgi", "dashboard.cgi", "index.cgi"):
            if found:
                break
            try:
                found = detect_model_in_html(self._get(page))
            except requests.HTTPError:
                continue
        if not found:
            raise ModelDetectionError(
                f"Could not identify the switch model at {self.host}; "
                f"pass model='GS308EP' (etc.) explicitly")
        log.debug("detected model: %s", found)
        return found

    # -- validation helpers ------------------------------------------------

    def _check_port(self, port: int):
        if port not in self.model.ports:
            raise ValueError(f"port {port} out of range 1..{self.model.port_count} for {self.model.name}")

    def _check_poe_port(self, port: int):
        if not self.model.has_poe:
            raise UnsupportedFeatureError(f"{self.model.name} has no PoE")
        if port not in self.model.poe_ports:
            raise ValueError(f"port {port} is not a PoE port on {self.model.name} "
                             f"(PoE ports: {list(self.model.poe_ports)})")

    def _require_poe(self):
        if not self.model.has_poe:
            raise UnsupportedFeatureError(f"{self.model.name} has no PoE")

    # -- PoE ---------------------------------------------------------------

    def get_poe_status(self) -> List[PoePortStatus]:
        self._require_poe()
        return parse_poe_status(self._get("getPoePortStatus.cgi"))

    def get_poe_settings(self) -> List[PoePortSetting]:
        self._require_poe()
        return parse_poe_settings(self._get("PoEPortConfig.cgi"))

    def get_poe_port_setting(self, port: int) -> PoePortSetting:
        self._check_poe_port(port)
        return self._find_poe_setting(self.get_poe_settings(), port)

    @staticmethod
    def _find_poe_setting(settings: List[PoePortSetting], port: int) -> PoePortSetting:
        for s in settings:
            if s.port == port:
                return s
        raise SwitchError(f"PoE settings page has no entry for port {port}")

    def set_poe_port(
        self,
        port: int,
        power: Optional[bool] = None,
        mode: Optional[str] = None,
        priority: Optional[str] = None,
        limit_type: Optional[str] = None,
        power_limit: Optional[str] = None,
        detect_type: Optional[str] = None,
        longer_detect: Optional[str] = None,
    ):
        """
        Update PoE settings for one port (1-based). Any argument left as None
        keeps the port's current value. `power=True/False` turns PoE on/off.
        """
        self._check_poe_port(port)

        def pick(mapping, new, current, default):
            return code_for(mapping, new if new is not None else current) or default

        def _attempt() -> str:
            html = self._get("PoEPortConfig.cgi")
            cur = self._find_poe_setting(parse_poe_settings(html), port)
            data = {
                "hash": _html.find_hash(html),
                "ACTION": "Apply",
                "portID": str(port - 1),
                "ADMIN_MODE": "1" if (power if power is not None else cur.power_enabled) else "0",
                "PORT_PRIO": pick(PORT_PRIO, priority, cur.priority, "0"),
                "POW_MOD": pick(PWR_MODE, mode, cur.power_mode, "0"),
                "POW_LIMT_TYP": pick(LIMIT_TYPE, limit_type, cur.limit_type, "0"),
                "POW_LIMT": power_limit if power_limit is not None else cur.power_limit,
                "DETEC_TYP": pick(DETEC_TYPE, detect_type, cur.detect_type, "2"),
                "DISCONNECT_TYP": pick(LONGER_DETECT, longer_detect, cur.longer_detect, "2"),
            }
            return self._post("PoEPortConfig.cgi", data)

        result = _attempt()
        if "SUCCESS" in result:
            return

        # A non-SUCCESS response (e.g. a stale cached session silently serving
        # a wrong/expired CSRF hash, which can surface as "CHECK HASH FAILED")
        # can happen even though the read+write happened within one call.
        # Force a fresh login and retry once with a freshly fetched hash.
        log.debug("PoE set port %d: non-SUCCESS response (%r); forcing fresh login and retrying",
                  port, result.strip()[:200])
        self.login()
        result2 = _attempt()
        if "SUCCESS" in result2:
            return

        # Some firmware applies the write before validating the CSRF hash, so
        # the port may have changed despite the error. Check real state
        # before reporting failure.
        if power is not None:
            try:
                if self.get_poe_port_setting(port).power_enabled == power:
                    log.debug("port %d: switch returned an error but the setting was applied", port)
                    return
            except SwitchError:
                pass
        raise SwitchError(f"PoE set failed for port {port} (after retry): {result2.strip()[:200]}")

    def poe_port_on(self, port: int):
        """Turn PoE power on for a port (1-based)."""
        self.set_poe_port(port, power=True)

    def poe_port_off(self, port: int):
        """Turn PoE power off for a port (1-based)."""
        self.set_poe_port(port, power=False)

    def poe_cycle(self, ports: Iterable[int]):
        """Power-cycle one or more PoE ports (1-based)."""
        ports = list(ports)
        for p in ports:
            self._check_poe_port(p)

        def _attempt() -> str:
            html = self._get("PoEPortConfig.cgi")
            data = {"hash": _html.find_hash(html), "ACTION": "Reset"}
            for p in ports:
                data[f"port{p - 1}"] = "checked"
            return self._post("PoEPortConfig.cgi", data)

        result = _attempt()
        if "SUCCESS" in result:
            return
        log.debug("PoE cycle: non-SUCCESS response (%r); forcing fresh login and retrying",
                  result.strip()[:200])
        self.login()
        result2 = _attempt()
        if "SUCCESS" not in result2:
            raise SwitchError(f"PoE cycle failed (after retry): {result2.strip()[:200]}")

    # -- 802.1Q VLANs ------------------------------------------------------

    def get_dot1q_enabled(self) -> bool:
        html = self._get("8021qCf.cgi")
        # Try 'name then checked then value' attribute order first...
        m = re.search(
            r'<input\b[^>]*\bname=["\']?status["\']?[^>]*\bchecked\b[^>]*\bvalue=["\'](\w+)["\']',
            html, re.IGNORECASE)
        if not m:
            # ...then 'value then name then checked' order.
            m = re.search(
                r'<input\b[^>]*\bvalue=["\'](\w+)["\'][^>]*\bname=["\']?status["\']?[^>]*\bchecked\b',
                html, re.IGNORECASE)
        return bool(m and m.group(1) == "Enable")

    def set_dot1q_enabled(self, enabled: bool):
        html = self._get("8021qCf.cgi")
        self._post("8021qCf.cgi", {
            "status": "Enable" if enabled else "Disable",
            "ACTION": "",
            "hash": _html.find_hash(html),
        })

    def get_vlan_ids(self) -> List[int]:
        html = self._get("8021qMembe.cgi")
        m = re.search(r'<select\b[^>]*\bname=["\']?VLAN_ID["\']?[^>]*>(.*?)</select>',
                      html, re.DOTALL | re.IGNORECASE)
        if not m:
            return []
        return [int(v) for v in re.findall(r'<option\b[^>]*\bvalue=["\']?(\d+)["\']?', m.group(1))]

    def _select_vlan(self, vid: int) -> str:
        """Select a VLAN on the membership page (mirrors the browser dropdown's onchange)."""
        html = self._get("8021qMembe.cgi")
        m = re.search(r'id="hiddenMem"[^>]*value="([^"]*)"', html, re.IGNORECASE)
        cur_mem = m.group(1) if m else MEMBER_NONE * self.port_count
        return self._post("8021qMembe.cgi", {
            "VLAN_ID": str(vid), "hiddenMem": cur_mem, "hash": _html.find_hash(html)})

    def get_vlan_membership(self, vid: int) -> str:
        """Return one char per port: '1' untagged, '2' tagged, '3' not a member."""
        text = self._select_vlan(vid)
        m = re.search(r'id="hiddenMem"[^>]*value="([^"]*)"', text, re.IGNORECASE)
        return m.group(1) if m else ""

    def set_vlan_membership(self, vid: int, membership):
        """
        Set port membership for a VLAN.

        `membership` may be given as a raw code string ('1'=untagged,
        '2'=tagged, '3'/'0'=none), or friendly tokens, e.g. on a 5-port model:
            sw.set_vlan_membership(10, "U,U,N,N,T")
            sw.set_vlan_membership(10, ["untagged", "untagged", "none", "none", "tagged"])
        """
        mem = normalize_membership(membership)
        if len(mem) != self.port_count:
            raise ValueError(f"membership must have {self.port_count} entries "
                             f"for {self.model.name}, got {len(mem)}")
        sel_text = self._select_vlan(vid)
        self._post("8021qMembe.cgi", {
            "VLAN_ID": str(vid), "hiddenMem": mem, "hash": _html.find_hash(sel_text)})

    def _vlan_config_form(self, html: str) -> Dict[str, str]:
        mgmt_m = re.search(r'name="MANAGEMENT_VLAN_ID"[^>]*value="(\d+)"', html)
        vnum_m = re.search(r"name=['\"]vlanNum['\"]\s+value=['\"](\d+)['\"]", html)
        return {
            "status": "Enable",
            "vlanNum": vnum_m.group(1) if vnum_m else "1",
            "MANAGEMENT_VLAN_ID": mgmt_m.group(1) if mgmt_m else "1",
            "hash": _html.find_hash(html),
        }

    def add_vlan(self, vid: int):
        """Create a new 802.1Q VLAN (enable 802.1Q mode first with set_dot1q_enabled)."""
        if not 1 <= vid <= 4093:
            raise ValueError(f"VLAN ID {vid} out of range 1..4093")
        html = self._get("8021qCf.cgi")
        self._post("8021qCf.cgi", {**self._vlan_config_form(html),
                                   "ADD_VLANID": str(vid), "ACTION": "Add"})

    def delete_vlan(self, vid: int):
        html = self._get("8021qCf.cgi")
        pairs = re.findall(r'name="(vlanck\d+)"[^>]*value="(\d+)"', html, re.IGNORECASE)
        ck_name = next((name for name, val in pairs if int(val) == vid), None)
        if ck_name is None:
            return  # nothing to delete
        self._post("8021qCf.cgi", {**self._vlan_config_form(html),
                                   ck_name: str(vid), "ACTION": "Delete"})

    # -- Port PVID ---------------------------------------------------------

    def get_port_pvids(self) -> Dict[int, int]:
        html = self._get("portPVID.cgi")
        result: Dict[int, int] = {}
        for row in re.findall(r'<tr\b[^>]*>(.*?)</tr>', html, re.DOTALL | re.IGNORECASE):
            cells = re.findall(r'<td\b[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
            nums = [t for t in (_html.strip_tags(c) for c in cells) if t.isdigit()]
            if len(nums) >= 2:
                result[int(nums[0])] = int(nums[1])
        return result

    def set_port_pvid(self, port: int, pvid: int):
        self._check_port(port)
        html = self._get("portPVID.cgi")
        self._post("portPVID.cgi", {
            f"port{port - 1}": "checked", "pvid": str(pvid), "hash": _html.find_hash(html)})

    # -- management IP -----------------------------------------------------

    def _dhcp_option(self, html: str, enabled: bool) -> str:
        """The dhcpMode <option> value meaning enabled/disabled on this firmware."""
        options = _html.select_options(html, "dhcpMode")
        want = "enable" if enabled else "disable"
        for value, label, _sel in options:
            if label.lower().startswith(want):
                return value
        raise SwitchError(f"can't find the DHCP {want} option on switch_info.cgi "
                          f"(options: {options}); run 'dump switch_info.cgi --full-html'")

    def _parse_ip_settings(self, html: str) -> IpSettings:
        selected = [value for value, _label, sel in _html.select_options(html, "dhcpMode") if sel]
        return IpSettings(
            dhcp=bool(selected) and selected[0] == self._dhcp_option(html, True),
            ip=_html.input_value(html, "ip_address"),
            netmask=_html.input_value(html, "subnet_mask"),
            gateway=_html.input_value(html, "gateway_address"),
        )

    def get_ip_settings(self) -> IpSettings:
        """The switch's management IP configuration."""
        return self._parse_ip_settings(self._get("switch_info.cgi"))

    def set_ip_settings(self, ip: Optional[str] = None, netmask: Optional[str] = None,
                        gateway: Optional[str] = None, dhcp: Optional[bool] = None,
                        verify_timeout: float = 20.0) -> Optional[IpSettings]:
        """
        Change the management IP configuration. Unspecified fields keep their
        current values.

        When the static address changes, the switch drops the connection
        mid-request; this then switches `self.host` to the new address and
        re-reads the settings from there, returning them. Your host needs a
        route to the new address, or verification fails with SwitchError.

        Enabling DHCP returns None: the new address is chosen by the DHCP
        server and can't be verified from here.

        A wrong address or gateway can make the switch unreachable; the only
        recovery is the reset button.
        """
        html = self._get("switch_info.cgi")
        cur = self._parse_ip_settings(html)
        new = IpSettings(dhcp=cur.dhcp if dhcp is None else dhcp, ip=ip or cur.ip,
                         netmask=netmask or cur.netmask, gateway=gateway or cur.gateway)
        if not new.dhcp:
            _validate_ip_settings(new)
        data = {
            "switch_name": _html.input_value(html, "switch_name"),
            "dhcpMode": self._dhcp_option(html, new.dhcp),
            "ip_address": new.ip,
            "subnet_mask": new.netmask,
            "gateway_address": new.gateway,
            "hash": _html.find_hash(html),
        }
        moving = new.dhcp != cur.dhcp or new.ip != cur.ip
        try:
            self._post("switch_info.cgi", data)
        except (requests.ConnectionError, requests.Timeout) as e:
            if not moving:
                raise
            log.debug("connection dropped while changing IP (expected): %s", e)

        if new.dhcp:
            return None if moving else self.get_ip_settings()
        if new.ip != cur.ip:
            self._set_host(new.ip)
        deadline = time.time() + verify_timeout
        while True:
            try:
                return self.get_ip_settings()
            except requests.RequestException as e:
                if time.time() >= deadline:
                    raise SwitchError(f"IP change sent, but the switch isn't answering at "
                                      f"{new.ip}: {e}") from e
                time.sleep(2)

    def _set_host(self, host: str):
        self.host = host
        self._session.headers.update({"Referer": self._url("index.cgi"),
                                      "Origin": f"http://{host}"})

    # -- diagnostics -------------------------------------------------------

    def discover_cgi_endpoints(self) -> Dict[str, object]:
        """
        Scrape likely menu/frame pages for every *.cgi link, plus probe a list
        of VLAN-related filenames seen across Netgear Plus-switch firmware
        families. Used to find the right endpoint names on firmware that
        differs from what this module assumes.
        """
        candidates_pages = [
            "", "index.cgi", "main.cgi", "menu.cgi", "dashboard.cgi",
            "top.cgi", "home.cgi", "status.cgi",
        ]
        found_links: set = set()
        page_results: Dict[str, object] = {}
        for path in candidates_pages:
            try:
                self._ensure_session()
                r = self._session.get(self._url(path), headers=self._headers(), timeout=self.timeout)
                page_results[path or "/"] = r.status_code
                if r.status_code == 200:
                    found_links.update(_cgi_links(r.text))
            except requests.RequestException as e:
                page_results[path or "/"] = f"error: {e}"

        vlan_candidates = [
            "8021qCf.cgi", "8021qMembe.cgi", "portPVID.cgi",
            "vlan.cgi", "vlanCfg.cgi", "vlanConfig.cgi",
            "qvlanBasic.cgi", "qvlanAdvance.cgi", "qvlanAdvanced.cgi",
            "qvlanPortCfg.cgi", "qvlanPVID.cgi", "qvlanMember.cgi",
            "dot1qBasicConfig.cgi", "dot1qAdvancedConfig.cgi",
            "dot1qEnable.cgi", "dot1qVlanMemberConfig.cgi", "dot1qVlanPvidConfig.cgi",
            "portBasedVlanBasic.cgi", "portBasedVlanAdvance.cgi",
            "vlanBasicMemberConfig.cgi", "vlanAdvancedMemberConfig.cgi",
            "vlanPortSet.cgi", "vlanPVIDConfig.cgi",
            "8021QDBasicVlanConfig.cgi", "8021QAdvanceVlanSetting.cgi",
        ]
        probe_results: Dict[str, object] = {}
        for name in vlan_candidates:
            try:
                self._ensure_session()
                r = self._session.get(self._url(name), headers=self._headers(), timeout=self.timeout)
                probe_results[name] = r.status_code
            except requests.RequestException as e:
                probe_results[name] = f"error: {e}"

        return {
            "menu_pages_checked": page_results,
            "cgi_links_found_in_menus": sorted(found_links),
            "vlan_endpoint_probe": probe_results,
        }

    def dump_page(self, path: str) -> Dict[str, object]:
        """
        Fetch an arbitrary *.cgi page (authenticated) and return its raw HTML
        plus a summary of forms/inputs/links found in it.
        """
        html = self._get(path)
        return {
            "path": path,
            "html_length": len(html),
            "forms": re.findall(r'<form\b[^>]*>', html, re.IGNORECASE),
            "inputs": re.findall(r'<input\b[^>]*>', html, re.IGNORECASE),
            "select_names": re.findall(r'<select\b[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*>',
                                       html, re.IGNORECASE),
            "cgi_links_found": sorted(_cgi_links(html)),
            "html": html,
        }

    def keepalive(self):
        try:
            self._session.get(self._url("getstatus.cgi"), headers=self._headers(),
                              timeout=self.timeout)
        except requests.RequestException:
            pass


def _validate_ip_settings(s: IpSettings):
    try:
        net = ipaddress.IPv4Network(f"{s.ip}/{s.netmask}", strict=False)
        gw = ipaddress.IPv4Address(s.gateway)
    except ValueError as e:
        raise ValueError(f"invalid IP settings: {e}") from e
    if s.gateway != "0.0.0.0" and gw not in net:
        raise ValueError(f"gateway {s.gateway} is not in {net}")


def _cgi_links(html: str) -> set:
    links = re.findall(r'''(?:href|src)=["']([^"']+\.cgi[^"']*)["']''', html, re.IGNORECASE)
    links += re.findall(r'''loadPage\(\s*["']([^"']+\.cgi)["']''', html, re.IGNORECASE)
    return {link.split("?")[0].lstrip("/") for link in links}
