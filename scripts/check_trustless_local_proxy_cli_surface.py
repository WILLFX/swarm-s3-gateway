#!/usr/bin/env python3
from pathlib import Path

cli = Path("trustless-proxy/src/cli.rs").read_text()
main = Path("trustless-proxy/src/main.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessCli",
    "LocalTrustlessCliCommand",
    "LocalTrustlessCliInput",
    "LocalTrustlessCliPreparedCommand",
    "LocalTrustlessCliError",
    "LocalTrustlessServerConfig",
    "LocalTrustlessServer::new",
    "prepare_from_args",
    "prepare_command",
    "network_bind_enabled",
    "network_bind_performed: false",
    "gateway_plaintext_access: false",
]

required_tests = [
    "cli_prepares_local_proxy_start_scaffold_without_network_bind",
    "cli_prepares_config_view_without_network_bind",
    "cli_parse_args_accepts_safe_local_proxy_flags",
    "cli_prepare_from_args_builds_server_config_boundary",
    "cli_rejects_network_bind_flag",
    "cli_rejects_invalid_listen_port",
    "cli_rejects_invalid_request_body_limit",
    "cli_rejects_unknown_command_and_unknown_flag",
    "cli_rejects_missing_flag_value",
]

required_lib = [
    "pub mod cli",
    "LocalTrustlessCli",
    "LocalTrustlessCliPreparedCommand",
]

required_main = [
    "LocalTrustlessCli::prepare_from_args",
    "std::env::args",
]

required_workflow = [
    "Check trustless local proxy CLI surface",
    "./scripts/check_trustless_local_proxy_cli_surface.py",
]

for token in required_source:
    if token not in cli:
        raise SystemExit(f"FAILED: missing CLI token: {token}")

for forbidden in [
    "TcpListener",
    "axum::",
    "hyper::",
    "tokio::net",
    "std::net",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in cli:
        raise SystemExit(f"FAILED: forbidden CLI token: {forbidden}")

for token in required_tests:
    if token not in cli:
        raise SystemExit(f"FAILED: missing CLI test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing CLI lib token: {token}")

for token in required_main:
    if token not in main:
        raise SystemExit(f"FAILED: missing CLI main token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing CLI workflow token: {token}")

print("Trustless local proxy CLI surface guard passed.")
