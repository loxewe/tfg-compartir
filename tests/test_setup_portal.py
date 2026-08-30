import importlib
import subprocess
from unittest.mock import Mock, call, patch

import pytest


with patch("subprocess.run"):
    setup_portal = importlib.import_module("setup_portal")


def test_import_does_not_change_router_state():
    with patch("subprocess.run") as run:
        importlib.reload(setup_portal)

    run.assert_not_called()


def test_main_stops_uhttpd_before_reset_and_server_start():
    operations = Mock()
    with (
        patch.object(setup_portal.subprocess, "run") as run,
        patch.object(setup_portal, "reset_router_state") as reset,
        patch.object(setup_portal, "cleanup_captive_dns") as cleanup,
        patch.object(setup_portal.app, "run") as serve,
    ):
        operations.attach_mock(run, "stop")
        operations.attach_mock(reset, "reset")
        operations.attach_mock(serve, "serve")
        result = setup_portal.main()

    assert result == 0
    assert operations.mock_calls == [
        call.stop(["/etc/init.d/uhttpd", "stop"], check=True, timeout=10),
        call.reset(),
        call.serve(host="0.0.0.0", port=80, debug=False, use_reloader=False),
    ]
    cleanup.assert_called_once_with()


def test_setup_marker_is_replaced_atomically(tmp_path):
    marker = tmp_path / ".setup_complete"

    with patch.object(setup_portal, "SETUP_MARKER", str(marker)):
        setup_portal.mark_setup_complete()

    assert marker.read_text(encoding="utf-8") == "completed\n"
    assert not (tmp_path / ".setup_complete.tmp").exists()


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(1, ["/etc/init.d/uhttpd", "stop"]),
        subprocess.TimeoutExpired(["/etc/init.d/uhttpd", "stop"], 10),
        FileNotFoundError("uhttpd is unavailable"),
    ],
)
def test_uhttpd_stop_failure_prevents_reset_and_server_start(error, capsys):
    with (
        patch.object(setup_portal.subprocess, "run", side_effect=error),
        patch.object(setup_portal, "reset_router_state") as reset,
        patch.object(setup_portal, "cleanup_captive_dns") as cleanup,
        patch.object(setup_portal.app, "run") as serve,
    ):
        result = setup_portal.main()

    assert result == 1
    reset.assert_not_called()
    serve.assert_not_called()
    assert "No se pudo detener uHTTPd" in capsys.readouterr().out


def test_reset_removes_policy_tables_before_enabling_native_dhcp():
    with patch.object(setup_portal.subprocess, "run") as run:
        setup_portal.reset_router_state()

    commands = [call.args[0] for call in run.call_args_list]
    delete_l2 = ["nft", "delete", "table", "netdev", "tfg_l2"]
    delete_l3 = ["nft", "delete", "table", "inet", "tfg_l3"]
    enable_dhcp = ["uci", "set", "dhcp.wifi.ignore=0"]

    assert delete_l2 in commands
    assert delete_l3 in commands
    assert commands.index(delete_l2) < commands.index(enable_dhcp)
    assert commands.index(delete_l3) < commands.index(enable_dhcp)


def test_failed_router_shutdown_preserves_setup_network():
    failed = subprocess.CompletedProcess([], returncode=1)

    with (
        patch.object(setup_portal.subprocess, "run", return_value=failed) as run,
        patch.object(setup_portal.subprocess, "Popen") as popen,
        patch.object(setup_portal.subprocess, "check_output") as check_output,
        patch.object(setup_portal.os, "_exit") as exit_process,
    ):
        setup_portal.finalize_takeover(
            "/switcher.py", "bad-password", "Home", "wifi-password", "glinet"
        )

    run.assert_called_once_with(
        ["python3", "/switcher.py", "bad-password", "off"],
        check=False,
        timeout=60,
    )
    popen.assert_not_called()
    check_output.assert_not_called()
    exit_process.assert_not_called()


def test_shutdown_execution_error_preserves_setup_network():
    with (
        patch.object(
            setup_portal.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("switcher", 60),
        ),
        patch.object(setup_portal.subprocess, "Popen") as popen,
        patch.object(setup_portal.os, "_exit") as exit_process,
    ):
        setup_portal.finalize_takeover(
            "/switcher.py", "password", "Home", "wifi-password", "glinet"
        )

    popen.assert_not_called()
    exit_process.assert_not_called()


def test_xiaomi_shutdown_requires_zero_exit_code():
    completed = subprocess.CompletedProcess([], returncode=0)

    with patch.object(
        setup_portal.subprocess, "run", return_value=completed
    ) as run:
        confirmed = setup_portal.shutdown_isp_router(
            "/xiaomi.py", "admin-password", "Home", "wifi-password", "xiaomi"
        )

    assert confirmed is True
    run.assert_called_once_with(
        [
            "python3",
            "/xiaomi.py",
            "admin-password",
            "wifi-password",
            "Home",
            "off",
        ],
        check=False,
        timeout=60,
    )


def test_successful_takeover_enables_selective_layer2_forwarding():
    completed = subprocess.CompletedProcess([], returncode=0)
    operations = Mock()

    with (
        patch.object(setup_portal, "shutdown_isp_router", return_value=True),
        patch.object(
            setup_portal.subprocess, "run", return_value=completed
        ) as run,
        patch.object(
            setup_portal.subprocess,
            "check_output",
            side_effect=[b"Setup", b"synthetic-password"],
        ),
        patch.object(setup_portal, "launch_detached") as launch,
        patch.object(setup_portal, "mark_setup_complete") as mark_complete,
        patch.object(setup_portal.os, "_exit") as exit_process,
        patch("time.sleep"),
    ):
        launch.return_value.poll.return_value = None
        operations.attach_mock(run, "run")
        operations.attach_mock(launch, "launch")
        operations.attach_mock(exit_process, "exit")
        setup_portal.finalize_takeover(
            "/switcher.py", "admin", "Home", "wifi-password", "glinet"
        )

    commands = [call.args[0] for call in run.call_args_list]
    assert ["uci", "set", "wireless.wifinet1.isolate=0"] in commands
    assert ["uci", "set", "wireless.wifinet1.bridge_isolate=0"] in commands
    launch.assert_called_once_with(
        "/root/tfg/controlador_aut.py", "/tmp/tfg-controller.log"
    )
    mark_complete.assert_called_once_with()
    assert operations.mock_calls.index(call.run(["wifi", "reload"])) < (
        operations.mock_calls.index(call.launch(
            "/root/tfg/controlador_aut.py", "/tmp/tfg-controller.log"
        ))
    ) < operations.mock_calls.index(call.exit(0))


def test_controller_early_exit_does_not_mark_setup(capsys):
    controller = Mock()
    controller.poll.return_value = 1

    with (
        patch.object(setup_portal, "shutdown_isp_router", return_value=True),
        patch.object(setup_portal.subprocess, "run"),
        patch.object(setup_portal.subprocess, "check_output", return_value=b"synthetic"),
        patch.object(setup_portal, "launch_detached", return_value=controller),
        patch.object(setup_portal, "mark_setup_complete") as mark_complete,
        patch.object(setup_portal.os, "_exit") as exit_process,
        patch("time.sleep"),
    ):
        setup_portal.finalize_takeover(
            "/switcher.py", "admin", "Home", "wifi-password", "glinet"
        )

    mark_complete.assert_not_called()
    exit_process.assert_not_called()
    assert "terminó durante el arranque" in capsys.readouterr().out


def test_detached_process_has_no_ssh_streams_and_appends_log(tmp_path):
    log_path = tmp_path / "process.log"

    def simulate_process(*args, **kwargs):
        kwargs["stdout"].write("registro de prueba\n")
        return Mock(pid=123)

    with patch.object(
        setup_portal.subprocess, "Popen", side_effect=simulate_process
    ) as popen:
        for _ in range(2):
            child = setup_portal.launch_detached(
                "/test/portal.py", str(log_path), "--background"
            )
            assert child.pid == 123

    for invocation in popen.call_args_list:
        assert invocation.args[0] == [
            setup_portal.sys.executable, "-u", "/test/portal.py", "--background"
        ]
        assert invocation.kwargs["start_new_session"] is True
        assert invocation.kwargs["stdin"] == subprocess.DEVNULL
        assert invocation.kwargs["stderr"] == subprocess.STDOUT
        assert invocation.kwargs["stdout"].closed
    assert log_path.read_text() == "registro de prueba\n" * 2
    if setup_portal.os.name == "posix":
        assert log_path.stat().st_mode & 0o777 == 0o600


def test_detached_launch_closes_log_on_spawn_error(tmp_path):
    with patch.object(
        setup_portal.subprocess, "Popen", side_effect=OSError("fallo simulado")
    ) as popen, pytest.raises(OSError):
        setup_portal.launch_detached("/test/portal.py", str(tmp_path / "test.log"))
    assert popen.call_args.kwargs["stdout"].closed


def test_portal_parent_detaches_before_any_router_changes(capsys):
    with (
        patch.object(setup_portal.sys, "argv", ["setup_portal.py"]),
        patch.object(setup_portal, "launch_detached", return_value=Mock(pid=123)) as launch,
        patch.object(setup_portal, "main") as main,
        patch.object(setup_portal.subprocess, "run") as run,
    ):
        assert setup_portal.launch_portal() == 0
    launch.assert_called_once_with(
        setup_portal.os.path.abspath(setup_portal.__file__),
        "/tmp/tfg-portal.log", "--background",
    )
    main.assert_not_called()
    run.assert_not_called()
    assert "/tmp/tfg-portal.log" in capsys.readouterr().out


def test_portal_child_runs_main_without_spawning_itself_again():
    with (
        patch.object(setup_portal.sys, "argv", ["setup_portal.py", "--background"]),
        patch.object(setup_portal, "launch_detached") as launch,
        patch.object(setup_portal, "main", return_value=1) as main,
    ):
        assert setup_portal.launch_portal() == 1
    main.assert_called_once_with()
    launch.assert_not_called()


def test_portal_spawn_failure_does_not_change_router_state(capsys):
    with (
        patch.object(setup_portal.sys, "argv", ["setup_portal.py"]),
        patch.object(setup_portal, "launch_detached", side_effect=OSError("fallo simulado")),
        patch.object(setup_portal, "main") as main,
        patch.object(setup_portal.subprocess, "run") as run,
    ):
        assert setup_portal.launch_portal() == 1
    main.assert_not_called()
    run.assert_not_called()
    assert "No se pudo lanzar el portal" in capsys.readouterr().out


def test_controller_spawn_failure_is_reported_without_claiming_completion(capsys):
    with (
        patch.object(setup_portal, "shutdown_isp_router", return_value=True),
        patch.object(setup_portal.subprocess, "run") as run,
        patch.object(setup_portal.subprocess, "check_output", return_value=b"synthetic"),
        patch.object(setup_portal, "launch_detached", side_effect=OSError("fallo simulado")),
        patch.object(setup_portal, "mark_setup_complete") as mark_complete,
        patch.object(setup_portal.os, "_exit") as exit_process,
        patch("time.sleep"),
    ):
        setup_portal.finalize_takeover(
            "/switcher.py", "admin", "Home", "wifi-password", "glinet"
        )
    exit_process.assert_not_called()
    mark_complete.assert_not_called()
    assert call(["/etc/init.d/uhttpd", "start"]) not in run.call_args_list
    assert "No se pudo lanzar el controlador" in capsys.readouterr().out
