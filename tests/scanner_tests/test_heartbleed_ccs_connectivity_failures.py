"""End-to-end checks that connectivity failures during the Heartbleed and CCS scans are surfaced by the Scanner.

The connectivity probe is mocked (the same approach as test_scanner.py) so that the mock raw-socket TLS servers only
have to emulate the behavior relevant to the two plugins under test.
"""

from unittest import mock

import pytest

from sslyze import (
    ClientAuthRequirementEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerTlsProbingResult,
)
from sslyze.json.json_output import ServerScanResultAsJson
from sslyze.scanner import _mass_connectivity_tester
from sslyze.server_connectivity import TlsVersionEnum
from tests.plugins_tests.mock_tls_server import (
    MockTlsServerBehaviorEnum,
    _MockTlsServer,
)

_SCAN_COMMANDS = {ScanCommand.HEARTBLEED, ScanCommand.OPENSSL_CCS_INJECTION}


def _run_scanner_against_mock_server(mock_server: _MockTlsServer):
    server_location = ServerNetworkLocation(
        hostname=mock_server.hostname, ip_address=mock_server.ip_address, port=mock_server.port
    )
    scan_request = ServerScanRequest(server_location=server_location, scan_commands=_SCAN_COMMANDS)

    # Pretend the connectivity probe succeeded and detected a TLS 1.2 server so the plugins do not short-circuit
    connectivity_result = ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
        cipher_suite_supported="ECDHE-RSA-AES128-GCM-SHA256",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=True,
    )

    with mock.patch.object(
        _mass_connectivity_tester, "check_connectivity_to_server", return_value=connectivity_result
    ):
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        all_results = list(scanner.get_results())

    assert len(all_results) == 1
    return all_results[0]


@pytest.mark.parametrize(
    "behavior",
    [
        MockTlsServerBehaviorEnum.CLOSE_BEFORE_ANY_RECORD,
        MockTlsServerBehaviorEnum.NEVER_REPLY,
    ],
)
def test_connectivity_failures_yield_error_attempts_and_null_json_results(behavior):
    # Given a target that cannot be fully tested (connection dropped before any record, or no response)
    with _MockTlsServer(behavior) as mock_server:
        # When running both scan commands through the Scanner
        server_scan_result = _run_scanner_against_mock_server(mock_server)

    # Then both attempts are reported as connectivity errors with no result
    for scan_command in _SCAN_COMMANDS:
        attempt = getattr(server_scan_result.scan_result, scan_command.value)
        assert attempt.status == ScanCommandAttemptStatusEnum.ERROR
        assert attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE
        assert attempt.error_trace
        assert attempt.result is None

    # And the JSON output keeps the boolean result field empty (null) instead of emitting a false "not vulnerable"
    json_model = ServerScanResultAsJson.model_validate(server_scan_result)
    json_dict = json_model.model_dump()
    for scan_command in _SCAN_COMMANDS:
        attempt_json = json_dict["scan_result"][scan_command.value]
        assert attempt_json["status"] == "ERROR"
        assert attempt_json["error_reason"] == "CONNECTIVITY_ISSUE"
        assert attempt_json["result"] is None

    # And the serialized JSON round-trips through the schema model
    assert ServerScanResultAsJson.model_validate_json(json_model.model_dump_json())


@pytest.mark.parametrize(
    "behavior",
    [
        MockTlsServerBehaviorEnum.REPLY_WITH_ALERT,
        MockTlsServerBehaviorEnum.CLOSE_AFTER_HANDSHAKE_FLIGHT,
    ],
)
def test_completable_scans_yield_not_vulnerable_boolean_results(behavior):
    # Given a target that replies properly (alert, or disconnects only after the handshake flight/payload exchange)
    with _MockTlsServer(behavior) as mock_server:
        # When running both scan commands through the Scanner
        server_scan_result = _run_scanner_against_mock_server(mock_server)

    # Then both attempts complete with an explicit not-vulnerable boolean result
    heartbleed_attempt = server_scan_result.scan_result.heartbleed
    assert heartbleed_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
    assert heartbleed_attempt.error_reason is None
    assert heartbleed_attempt.result.is_vulnerable_to_heartbleed is False

    ccs_attempt = server_scan_result.scan_result.openssl_ccs_injection
    assert ccs_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
    assert ccs_attempt.error_reason is None
    assert ccs_attempt.result.is_vulnerable_to_ccs_injection is False

    # And the JSON output carries the boolean values (backward-compatible shape)
    json_dict = ServerScanResultAsJson.model_validate(server_scan_result).model_dump()
    assert json_dict["scan_result"]["heartbleed"]["result"] == {"is_vulnerable_to_heartbleed": False}
    assert json_dict["scan_result"]["openssl_ccs_injection"]["result"] == {
        "is_vulnerable_to_ccs_injection": False
    }
