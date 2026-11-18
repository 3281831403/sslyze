import pytest

from sslyze import ClientAuthRequirementEnum
from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.plugins.openssl_ccs_injection_plugin import (
    OpenSslCcsInjectionImplementation,
    OpenSslCcsInjectionScanResult,
    OpenSslCcsInjectionScanResultAsJson,
)
from sslyze.server_connectivity import ServerConnectivityInfo, ServerTlsProbingResult, TlsVersionEnum
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, LegacyOpenSslServer
from tests.plugins_tests.mock_tls_server import (
    MockTlsServerBehaviorEnum,
    _MockTlsServer,
    build_tls_1_2_server_info,
)


class TestOpenSslCcsInjectionPluginConnectionFailures:
    """The plugin must not return a "not vulnerable" result when the test could not be completed."""

    def test_close_before_any_record_is_a_connectivity_error(self):
        # Given a server (or middlebox) that closes the connection before sending back a single TLS record
        with _MockTlsServer(MockTlsServerBehaviorEnum.CLOSE_BEFORE_ANY_RECORD) as server:
            server_info = build_tls_1_2_server_info(server)

            # When testing for CCS injection, the scan does NOT produce a result
            with pytest.raises(ServerRejectedTlsHandshake):
                OpenSslCcsInjectionImplementation.scan_server(server_info)

    def test_no_response_is_a_connectivity_error(self):
        # Given a server that accepts the connection but never responds
        with _MockTlsServer(MockTlsServerBehaviorEnum.NEVER_REPLY) as server:
            server_info = build_tls_1_2_server_info(server)

            # When testing for CCS injection, the scan times out and does NOT produce a result
            with pytest.raises(ServerRejectedTlsHandshake):
                OpenSslCcsInjectionImplementation.scan_server(server_info)

    def test_tls_alert_means_not_vulnerable(self):
        # Given a modern server that rejects the probe with a TLS alert
        with _MockTlsServer(MockTlsServerBehaviorEnum.REPLY_WITH_ALERT) as server:
            server_info = build_tls_1_2_server_info(server)

            # When testing for CCS injection, it completes and the server is reported as not vulnerable
            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

            assert isinstance(result, OpenSslCcsInjectionScanResult)
            assert not result.is_vulnerable_to_ccs_injection

            # And the result can still be serialized to JSON
            assert OpenSslCcsInjectionScanResultAsJson.model_validate(result).model_dump_json()

    def test_disconnect_after_handshake_flight_means_not_vulnerable(self):
        # Given a server that completes its handshake flight and only disconnects after receiving the early CCS
        with _MockTlsServer(MockTlsServerBehaviorEnum.CLOSE_AFTER_HANDSHAKE_FLIGHT) as server:
            server_info = build_tls_1_2_server_info(server)

            # When testing for CCS injection, it completes and the server is reported as not vulnerable
            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

            assert not result.is_vulnerable_to_ccs_injection

    def test_tls_1_3_short_circuit_still_returns_not_vulnerable(self):
        # Given a server whose highest supported version is TLS 1.3 (so it cannot be vulnerable)
        server_location = ServerNetworkLocation(hostname="unreachable.example", ip_address="192.0.2.10", port=443)
        server_info = ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="unreachable.example"),
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
                cipher_suite_supported="TLS_AES_256_GCM_SHA384",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
                supports_ecdh_key_exchange=True,
            ),
        )

        # When testing for CCS injection, it short-circuits without opening any connection
        result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        assert not result.is_vulnerable_to_ccs_injection


class TestOpenSslCcsInjectionPlugin:
    @can_only_run_on_linux_64
    def test_vulnerable(self):
        # Given a server that is vulnerable to CCS injection
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            from tests.connectivity_utils import check_connectivity_to_server_and_return_info

            server_info = check_connectivity_to_server_and_return_info(server_location)

            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        assert result.is_vulnerable_to_ccs_injection
        assert OpenSslCcsInjectionImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_vulnerable_and_server_has_sni_bug(self):
        # Test for https://github.com/nabla-c0d3/sslyze/issues/202
        server_name_indication = "server.com"
        with LegacyOpenSslServer(require_server_name_indication_value=server_name_indication) as server:
            server_location = ServerNetworkLocation(
                hostname=server_name_indication, ip_address=server.ip_address, port=server.port
            )
            from tests.connectivity_utils import check_connectivity_to_server_and_return_info

            server_info = check_connectivity_to_server_and_return_info(server_location)
            object.__setattr__(server_info.network_configuration, "tls_server_name_indication", "wrongvalue.com")

            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        assert result.is_vulnerable_to_ccs_injection

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self):
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            from tests.connectivity_utils import check_connectivity_to_server_and_return_info

            server_info = check_connectivity_to_server_and_return_info(server_location)

            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        assert result.is_vulnerable_to_ccs_injection
