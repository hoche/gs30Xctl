import pytest

from gs30xctl import (MODELS, IpSettings, Switch, UnsupportedFeatureError, detect_model_in_html,
                      encrypt_password, get_model, membership_to_labels, normalize_membership)
from gs30xctl.poe import parse_poe_settings

LOGIN_PAGE = """<html><head><title>NETGEAR {model}</title></head>
<body><form action="login.cgi"><input type=hidden id='rand' value='1234567'></form></body></html>"""

POE_SETTINGS_PAGE = "".join(
    f"""<li class="poePortSettingListItem">
    <input type="hidden" class="port" value="{p}">
    <input type="hidden" class="portName" value="cam{p}">
    <input type="hidden" id="hidPortPwr" value="{1 if p % 2 else 0}">
    <input type="hidden" id="hidPwrMode" value="3">
    <input type="hidden" id="hidPortPrio" value="0">
    <input type="hidden" id="hidLimitType" value="2">
    <input type="hidden" class="pwrLimit" value="30.0">
    <input type="hidden" id="hidDetecType" value="2">
    <input type="hidden" class="longerDetect" value="2">
    </li>""" for p in range(1, 5)) + '<input type="hidden" id="hash" value="999">'


class FakeResponse:
    def __init__(self, text="", headers=None, status_code=200):
        self.text, self.headers, self.status_code = text, headers or {}, status_code
        self.ok = status_code < 400

    def raise_for_status(self):
        if not self.ok:
            import requests
            raise requests.HTTPError(self.status_code)


class FakeSession:
    """Minimal stand-in for requests.Session that routes by (method, path)."""

    def __init__(self, model="GS305EP", pages=None):
        self.headers = {}
        self.calls = []
        self.pages = {("GET", "login.cgi"): FakeResponse(LOGIN_PAGE.format(model=model)),
                      ("POST", "login.cgi"): FakeResponse("", {"Set-Cookie": "SID=abc123; path=/"})}
        self.pages.update(pages or {})

    def request(self, method, url, data=None, headers=None, timeout=None):
        path = url.split("/", 3)[3]
        self.calls.append((method, path, data, headers))
        return self.pages.get((method, path), FakeResponse("", status_code=404))

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


# -- models -------------------------------------------------------------------

@pytest.mark.parametrize("name", list(MODELS))
def test_detect_every_model_from_login_title(name):
    assert detect_model_in_html(LOGIN_PAGE.format(model=name)).name == name


def test_detect_prefers_longest_suffix_and_title():
    assert detect_model_in_html("<title>GS308EPP</title>").name == "GS308EPP"
    assert detect_model_in_html("<title>NETGEAR GS305E</title> GS308EP").name == "GS305E"
    assert detect_model_in_html("<title>Switch</title>") is None


def test_model_properties():
    assert get_model("gs305ep").poe_ports == (1, 2, 3, 4)
    assert get_model("GS308EPP").port_count == 8 and get_model("GS308EPP").has_poe
    assert not get_model("GS308E").has_poe
    with pytest.raises(ValueError):
        get_model("GS108E")


# -- helpers ------------------------------------------------------------------

def test_encrypt_password():
    # password "pas" interleaved with seed "12" -> "p1a2s"
    import hashlib
    assert encrypt_password("pas", "12") == hashlib.md5(b"p1a2s").hexdigest()


def test_membership():
    assert normalize_membership("U,U,N,N,T") == "11332"
    assert normalize_membership(["tagged", "none"]) == "23"
    assert normalize_membership("12331") == "12331"
    assert membership_to_labels("123") == ["untagged", "tagged", "none"]
    with pytest.raises(ValueError):
        normalize_membership("U,X")


def test_parse_poe_settings():
    settings = parse_poe_settings(POE_SETTINGS_PAGE)
    assert [s.port for s in settings] == [1, 2, 3, 4]
    assert settings[0].power_enabled and not settings[1].power_enabled
    assert settings[0].power_mode == "802.3at" and settings[0].limit_type == "user"
    assert settings[2].name == "cam3"


# -- client (offline, with a fake HTTP session) --------------------------------

def test_login_detects_model_and_sets_cookie():
    sess = FakeSession("GS308E")
    sw = Switch("sw", "pw", session=sess)
    sw.login()
    assert sw.session_id == "abc123"
    assert sw.model.name == "GS308E" and sw.port_count == 8
    assert sess.calls[1][2] == {"password": encrypt_password("pw", "1234567")}


def test_legacy_cookie_name_is_echoed_back():
    sess = FakeSession("GS308E", {("POST", "login.cgi"): FakeResponse("", {"Set-Cookie": "GS108SID=zz"}),
                                  ("GET", "portPVID.cgi"): FakeResponse("<table></table>")})
    sw = Switch("sw", "pw", session=sess)
    sw.get_port_pvids()
    assert sess.calls[-1][3] == {"Cookie": "GS108SID=zz"}


def test_poe_rejected_on_non_poe_model():
    sw = Switch("sw", "pw", model="GS305E", session=FakeSession("GS305E"))
    with pytest.raises(UnsupportedFeatureError):
        sw.get_poe_status()
    with pytest.raises(UnsupportedFeatureError):
        sw.poe_port_off(1)


def test_poe_rejects_non_poe_port():
    sw = Switch("sw", "pw", model="GS305EP", session=FakeSession())
    with pytest.raises(ValueError, match="not a PoE port"):
        sw.poe_port_off(5)


def test_set_poe_port_posts_expected_form():
    sess = FakeSession("GS305EP", {("GET", "PoEPortConfig.cgi"): FakeResponse(POE_SETTINGS_PAGE),
                                   ("POST", "PoEPortConfig.cgi"): FakeResponse("SUCCESS")})
    sw = Switch("sw", "pw", session=sess)
    sw.poe_port_off(3)
    method, path, data, _ = sess.calls[-1]
    assert (method, path) == ("POST", "PoEPortConfig.cgi")
    assert data["portID"] == "2" and data["ADMIN_MODE"] == "0" and data["hash"] == "999"
    assert data["POW_MOD"] == "3" and data["POW_LIMT_TYP"] == "2" and data["POW_LIMT"] == "30.0"


def test_membership_length_checked_against_model():
    sw = Switch("sw", "pw", model="GS308EP", session=FakeSession("GS308EP"))
    with pytest.raises(ValueError, match="8 entries"):
        sw.set_vlan_membership(10, "U,U,N,N,T")


# -- management IP ------------------------------------------------------------

def switch_info_page(dhcp=False, ip="192.168.0.239"):
    sel = ('<option value="0"{}>Disable</option><option value="1"{}>Enable</option>'
           .format("" if dhcp else " selected", " selected" if dhcp else ""))
    return f"""<form method="post" action="/switch_info.cgi">
    <input type="text" name="switch_name" id="switch_name" value="lab" size="15">
    <select name="dhcpMode" id="dhcpMode">{sel}</select>
    <input type="text" name="ip_address" id="ip_address" value="{ip}" size="15">
    <input type="text" name="subnet_mask" id="subnet_mask" value="255.255.255.0">
    <input type="text" name="gateway_address" id="gateway_address" value="192.168.0.254">
    <input type=hidden name='hash' id='hash' value="11364"></form>"""


class DroppingSession(FakeSession):
    """Drops the connection on the IP-change POST, then serves the new address."""

    def request(self, method, url, data=None, headers=None, timeout=None):
        self.urls = getattr(self, "urls", []) + [url]
        if (method, url.split("/", 3)[3]) == ("POST", "switch_info.cgi"):
            import requests
            self.calls.append((method, "switch_info.cgi", data, headers))
            self.pages[("GET", "switch_info.cgi")] = FakeResponse(
                switch_info_page(ip=data["ip_address"]))
            raise requests.ConnectionError("reset by peer")
        return super().request(method, url, data, headers, timeout)


def test_get_ip_settings():
    sess = FakeSession("GS305E", {("GET", "switch_info.cgi"): FakeResponse(switch_info_page())})
    s = Switch("sw", "pw", session=sess).get_ip_settings()
    assert s == IpSettings(dhcp=False, ip="192.168.0.239", netmask="255.255.255.0",
                           gateway="192.168.0.254")
    sess.pages[("GET", "switch_info.cgi")] = FakeResponse(switch_info_page(dhcp=True))
    assert Switch("sw", "pw", session=sess).get_ip_settings().dhcp


def test_set_ip_moves_host_and_verifies():
    sess = DroppingSession("GS305E", {("GET", "switch_info.cgi"): FakeResponse(switch_info_page())})
    sw = Switch("192.168.0.239", "pw", session=sess)
    s = sw.set_ip_settings(ip="192.168.0.240")
    post = next(c for c in sess.calls if c[:2] == ("POST", "switch_info.cgi"))
    assert post[2] == {"switch_name": "lab", "dhcpMode": "0", "ip_address": "192.168.0.240",
                       "subnet_mask": "255.255.255.0", "gateway_address": "192.168.0.254",
                       "hash": "11364"}
    assert sw.host == "192.168.0.240" and s.ip == "192.168.0.240"
    assert sess.urls[-1] == "http://192.168.0.240/switch_info.cgi"
    assert sess.headers["Origin"] == "http://192.168.0.240"


def test_set_ip_rejects_gateway_outside_subnet():
    sess = FakeSession("GS305E", {("GET", "switch_info.cgi"): FakeResponse(switch_info_page())})
    with pytest.raises(ValueError, match="not in"):
        Switch("sw", "pw", session=sess).set_ip_settings(ip="10.0.0.5")
    assert not any(c[0] == "POST" and c[1] == "switch_info.cgi" for c in sess.calls)
