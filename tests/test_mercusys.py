import importlib
import json
from unittest.mock import Mock, patch

import pytest
import requests


mercusys = importlib.import_module(
    "Scripts_Finales.Mercusys_TPLink.conmutar_mercusys"
)


@pytest.mark.parametrize("action", ["on", "off"])
def test_wireless_request_uses_router_ip(action):
    session = Mock()
    session.post.side_effect = requests.exceptions.ConnectionError("test disconnect")
    login = (session, "test-token", "key", "iv", "hash", 1, "n", "e")
    with (
        patch.object(mercusys, "do_login", return_value=login),
        patch.object(mercusys, "aes_encrypt", return_value="encrypted"),
        patch.object(mercusys, "get_rsa_signature", return_value="signature"),
        patch.object(
            mercusys.sys, "argv", ["switcher.py", "test-password", action]
        ),
    ):
        mercusys.main()

    session.post.assert_called_once()
    url = session.post.call_args.args[0]
    assert url.startswith("http://192.168.0.1/cgi-bin/luci/")
    assert "/admin/wireless?form=wireless_2g&form=wireless_5g" in url


@pytest.mark.parametrize("action", ["on", "off"])
@pytest.mark.parametrize("logout_result", ["success", "rejected", "timeout"])
def test_logout_after_wifi_change(action, logout_result, capsys):
    key, iv = "0123456789012345", "5432109876543210"
    session = Mock()
    wifi_response = Mock()
    wifi_response.json.return_value = {
        "data": mercusys.aes_encrypt(json.dumps({"success": True}), key, iv)
    }
    logout_response = Mock()
    logout_response.json.return_value = {
        "data": mercusys.aes_encrypt(
            json.dumps({"success": logout_result == "success"}), key, iv
        )
    }
    session.post.side_effect = [
        wifi_response,
        requests.Timeout() if logout_result == "timeout" else logout_response,
    ]
    login = (session, "test-token", key, iv, "hash", 1, "n", "e")
    with (
        patch.object(mercusys, "do_login", return_value=login),
        patch.object(mercusys, "aes_encrypt", return_value="encrypted") as encrypt,
        patch.object(mercusys, "get_rsa_signature", return_value="signature"),
        patch.object(mercusys.sys, "argv", ["switcher.py", "test-password", action]),
    ):
        assert mercusys.main() == 0

    assert session.post.call_count == 2
    wifi_call, logout_call = session.post.call_args_list
    assert "/admin/wireless?" in wifi_call.args[0]
    assert logout_call.args[0] == (
        "http://192.168.0.1/cgi-bin/luci/;stok=test-token/admin/system?form=logout"
    )
    assert wifi_call.kwargs["timeout"] is None
    assert logout_call.kwargs["timeout"] == 3
    assert encrypt.call_args.args == ("", key, iv)
    output = capsys.readouterr().out
    assert ("Sesión cerrada." in output) == (logout_result == "success")
    if logout_result != "success":
        assert "no ha confirmado" in output or "No se ha podido confirmar" in output
