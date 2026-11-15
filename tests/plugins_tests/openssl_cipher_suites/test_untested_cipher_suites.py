from unittest import mock

import pytest

from sslyze import ScanCommand, ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum, ServerScanRequest
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteNotTested,
    CipherSuiteRejectedByServer,
    _set_cipher_suite_string,
    connect_with_cipher_suite,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.plugins.openssl_cipher_suites.implementation import Tlsv13ScanImplementation
from sslyze.plugins.openssl_cipher_suites.json_output import CipherSuitesScanResultAsJson
from sslyze.plugins.plugin_base import ScanJobResult
from sslyze.scanner import _mass_connectivity_tester
from sslyze.scanner.scanner import Scanner
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation
from tests.accept_only_server import AcceptOnlyServer
from tests.factories import ServerConnectivityInfoFactory, ServerTlsProbingResultFactory


_ALL_TLS_1_3_CIPHER_SUITES = sorted(
    CipherSuitesRepository.get_all_cipher_suites(TlsVersionEnum.TLS_1_3), key=lambda cipher_suite: cipher_suite.name
)


def _generate_scan_job_results(
    accepted_cipher_suites: int = 0,
    rejected_cipher_suites: int = 0,
    untested_cipher_suites: int = 0,
) -> list[ScanJobResult]:
    assert accepted_cipher_suites + rejected_cipher_suites + untested_cipher_suites == len(_ALL_TLS_1_3_CIPHER_SUITES)

    all_job_results = []
    cipher_suites = iter(_ALL_TLS_1_3_CIPHER_SUITES)
    for _ in range(accepted_cipher_suites):
        all_job_results.append(
            ScanJobResult(
                _return_value=CipherSuiteAcceptedByServer(cipher_suite=next(cipher_suites), ephemeral_key=None),
                _exception=None,
            )
        )
    for _ in range(rejected_cipher_suites):
        all_job_results.append(
            ScanJobResult(
                _return_value=CipherSuiteRejectedByServer(
                    cipher_suite=next(cipher_suites), error_message="TLS alert: handshake failure"
                ),
                _exception=None,
            )
        )
    for _ in range(untested_cipher_suites):
        all_job_results.append(
            ScanJobResult(
                _return_value=CipherSuiteNotTested(
                    cipher_suite=next(cipher_suites),
                    error_message="Connection to server timed out during the TLS handshake",
                ),
                _exception=None,
            )
        )
    return all_job_results


class TestCipherSuitesScanResultWithUntestedCipherSuites:
    def test_no_untested_cipher_suites(self):
        # Given a scan where all the cipher suites could be tested
        scan_job_results = _generate_scan_job_results(accepted_cipher_suites=2, rejected_cipher_suites=3)

        # When generating the result
        result = Tlsv13ScanImplementation.result_for_completed_scan_jobs(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_job_results=scan_job_results,
        )

        # The untested list is empty
        assert len(result.accepted_cipher_suites) == 2
        assert len(result.rejected_cipher_suites) == 3
        assert result.untested_cipher_suites == []

    def test_partially_untested_cipher_suites(self):
        # Given a scan where only some cipher suites could be tested
        scan_job_results = _generate_scan_job_results(
            accepted_cipher_suites=1, rejected_cipher_suites=2, untested_cipher_suites=2
        )

        # When generating the result
        result = Tlsv13ScanImplementation.result_for_completed_scan_jobs(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_job_results=scan_job_results,
        )

        # The results for the cipher suites that could be tested are kept
        assert len(result.accepted_cipher_suites) == 1
        assert len(result.rejected_cipher_suites) == 2

        # And the cipher suites that could not be tested are listed separately
        assert len(result.untested_cipher_suites) == 2
        assert all(isinstance(untested, CipherSuiteNotTested) for untested in result.untested_cipher_suites)

        # And the accepted/rejected/untested lists are disjoint
        tested_cipher_suite_names = {accepted.cipher_suite.name for accepted in result.accepted_cipher_suites}
        tested_cipher_suite_names.update(rejected.cipher_suite.name for rejected in result.rejected_cipher_suites)
        untested_cipher_suite_names = {untested.cipher_suite.name for untested in result.untested_cipher_suites}
        assert not tested_cipher_suite_names.intersection(untested_cipher_suite_names)
        assert len(tested_cipher_suite_names | untested_cipher_suite_names) == len(_ALL_TLS_1_3_CIPHER_SUITES)

        # And a CLI output can be generated, which lists the untested cipher suites
        cli_output = Tlsv13ScanImplementation.cli_connector_cls.result_to_console_output(result)
        cli_output_as_str = "\n".join(cli_output)
        assert "could not be tested" in cli_output_as_str
        for untested in result.untested_cipher_suites:
            assert untested.cipher_suite.name in cli_output_as_str

        # And the result can be converted to JSON, with the untested cipher suites
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result)
        assert len(result_as_json.untested_cipher_suites) == 2
        assert "untested_cipher_suites" in result_as_json.model_dump_json()

    def test_all_cipher_suites_untested(self):
        # Given a scan where no cipher suite could be tested
        scan_job_results = _generate_scan_job_results(untested_cipher_suites=5)
        server_info = ServerConnectivityInfoFactory.create()

        # When generating the result, a connectivity error is raised
        # This ensures the scan command attempt gets marked as CONNECTIVITY_ISSUE with no result
        with pytest.raises(TlsHandshakeTimedOut):
            Tlsv13ScanImplementation.result_for_completed_scan_jobs(
                server_info=server_info,
                scan_job_results=scan_job_results,
            )


class TestCipherSuiteUntestedAsJson:
    def test_parse_json_output_without_untested_cipher_suites(self):
        # Given a JSON result generated by an older version of SSLyze, without the untested_cipher_suites field
        result_as_json = CipherSuitesScanResultAsJson.model_validate(
            {
                "tls_version_used": "TLS_1_3",
                "is_tls_version_supported": False,
                "accepted_cipher_suites": [],
                "rejected_cipher_suites": [],
            }
        )

        # It can still be parsed, with an empty untested_cipher_suites list
        assert result_as_json.untested_cipher_suites == []


class TestConnectWithCipherSuiteRetries:
    def test_rejected_cipher_suite_is_not_retried(self):
        # Given a server that explicitly rejects the cipher suite
        server_info = ServerConnectivityInfoFactory.create()
        cipher_suite = _ALL_TLS_1_3_CIPHER_SUITES[0]

        with mock.patch.object(
            ServerConnectivityInfo,
            "get_preconfigured_tls_connection",
            wraps=server_info.get_preconfigured_tls_connection,
        ) as mocked_connection_getter:
            with mock.patch("sslyze.connection_helpers.tls_connection.SslConnection.connect") as mocked_connect:
                mocked_connect.side_effect = _raise_server_rejected_handshake(server_info)

                # When testing the cipher suite
                result = connect_with_cipher_suite(server_info, TlsVersionEnum.TLS_1_3, cipher_suite)

        # The cipher suite is reported as rejected, and only one attempt was made
        assert isinstance(result, CipherSuiteRejectedByServer)
        assert mocked_connection_getter.call_count == 1
        assert mocked_connect.call_count == 1

    def test_handshake_timeout_is_retried(self):
        # Given a server for which the TLS handshake keeps timing out
        server_info = ServerConnectivityInfoFactory.create()
        cipher_suite = _ALL_TLS_1_3_CIPHER_SUITES[0]
        max_retries = server_info.network_configuration.network_max_retries

        # And each attempt only enables the cipher suite being tested
        all_cipher_lists_used = []
        original_set_cipher_suite_string = _set_cipher_suite_string

        def _record_cipher_list(tls_version, cipher_suite_str, ssl_client):
            all_cipher_lists_used.append(cipher_suite_str)
            original_set_cipher_suite_string(tls_version, cipher_suite_str, ssl_client)

        with mock.patch.object(
            ServerConnectivityInfo,
            "get_preconfigured_tls_connection",
            wraps=server_info.get_preconfigured_tls_connection,
        ) as mocked_connection_getter:
            with mock.patch("sslyze.connection_helpers.tls_connection.SslConnection.connect") as mocked_connect:
                mocked_connect.side_effect = _raise_handshake_timed_out(server_info)
                with mock.patch(
                    "sslyze.plugins.openssl_cipher_suites._test_cipher_suite._set_cipher_suite_string",
                    side_effect=_record_cipher_list,
                ):
                    # When testing the cipher suite
                    result = connect_with_cipher_suite(server_info, TlsVersionEnum.TLS_1_3, cipher_suite)

        # The cipher suite is reported as not tested, and the scan was retried as many times as configured
        assert isinstance(result, CipherSuiteNotTested)
        assert mocked_connect.call_count == max_retries
        assert mocked_connection_getter.call_count == max_retries

        # And every retry used the same, single cipher suite being tested
        assert all_cipher_lists_used == [cipher_suite.openssl_name] * max_retries

    def test_handshake_timeout_then_success(self):
        # Given a server for which the TLS handshake times out once, and then succeeds
        server_info = ServerConnectivityInfoFactory.create()
        cipher_suite = _ALL_TLS_1_3_CIPHER_SUITES[0]

        handshake_attempts_count = 0

        def _time_out_then_succeed() -> None:
            nonlocal handshake_attempts_count
            handshake_attempts_count += 1
            if handshake_attempts_count == 1:
                raise _handshake_timed_out(server_info)
            # Do nothing on the second attempt; the handshake "succeeded"

        with mock.patch(
            "sslyze.connection_helpers.tls_connection.SslConnection.connect",
            side_effect=_time_out_then_succeed,
        ) as mocked_connect:
            with mock.patch("sslyze.connection_helpers.tls_connection.SslConnection.close", return_value=None):
                with mock.patch("nassl.ssl_client.BaseSslClient.get_ephemeral_key", return_value=None):
                    # When testing the cipher suite
                    result = connect_with_cipher_suite(server_info, TlsVersionEnum.TLS_1_3, cipher_suite)

        # The cipher suite is reported as accepted
        assert isinstance(result, CipherSuiteAcceptedByServer)
        assert mocked_connect.call_count == 2


class TestCipherSuitesScanCommandWithAcceptOnlyServer:
    def test_accept_only_server_all_tls_1_3_cipher_suites_untested(self):
        # Given a server that accepts TCP connections but never replies to the TLS ClientHello
        with AcceptOnlyServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            network_configuration = ServerNetworkConfiguration(
                tls_server_name_indication=server.hostname,
                network_timeout=1,
                network_max_retries=2,
            )
            server_info = ServerConnectivityInfo(
                server_location=server_location,
                network_configuration=network_configuration,
                tls_probing_result=ServerTlsProbingResultFactory.create(),
            )

            # When testing TLS 1.3 cipher suites directly
            # Then all the handshakes timed out and no conclusion could be reached
            with pytest.raises(TlsHandshakeTimedOut):
                Tlsv13ScanImplementation.scan_server(server_info)

            # And every cipher suite was retried according to network_max_retries
            assert server.accepted_connections_count == 5 * network_configuration.network_max_retries

    def test_accept_only_server_scan_command_gets_connectivity_issue(self):
        # Given a server that accepts TCP connections but never replies to the TLS ClientHello
        with AcceptOnlyServer() as server:
            scan_request = ServerScanRequest(
                server_location=ServerNetworkLocation(
                    hostname=server.hostname, ip_address=server.ip_address, port=server.port
                ),
                network_configuration=ServerNetworkConfiguration(
                    tls_server_name_indication=server.hostname,
                    network_timeout=1,
                    network_max_retries=1,
                ),
                scan_commands={ScanCommand.TLS_1_3_CIPHER_SUITES},
            )

            # And the connectivity test succeeded, using TLS 1.2 as the highest version supported
            connectivity_result = ServerTlsProbingResultFactory.create()
            with mock.patch.object(
                _mass_connectivity_tester, "check_connectivity_to_server", return_value=connectivity_result
            ):
                # When running the scan
                scanner = Scanner()
                scanner.queue_scans([scan_request])
                all_scan_results = list(scanner.get_results())

        # Then the scan completed
        assert len(all_scan_results) == 1
        # But the TLS 1.3 cipher suites scan command reported a connectivity issue, with no result
        tls_1_3_attempt = all_scan_results[0].scan_result.tls_1_3_cipher_suites
        assert tls_1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR
        assert tls_1_3_attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE
        assert tls_1_3_attempt.error_trace
        assert tls_1_3_attempt.result is None


def _raise_server_rejected_handshake(server_info: ServerConnectivityInfo) -> Exception:
    return ServerRejectedTlsHandshake(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message="TLS alert: handshake failure",
    )


def _handshake_timed_out(server_info: ServerConnectivityInfo) -> TlsHandshakeTimedOut:
    return TlsHandshakeTimedOut(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message="Connection to server timed out during the TLS handshake",
    )


def _raise_handshake_timed_out(server_info: ServerConnectivityInfo) -> Exception:
    return _handshake_timed_out(server_info)
