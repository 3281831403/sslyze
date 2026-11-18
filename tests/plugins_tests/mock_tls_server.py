"""Minimal raw-socket TLS servers used to test the Heartbleed and CCS injection plugins.

These servers do NOT implement a real TLS stack. They only behave in specific ways once a TCP connection has been
established and the client has sent its ClientHello, which is enough to exercise how the plugins react to:

- a server that never replies (middlebox silently dropping the traffic);
- a server that closes the connection before sending a single TLS record;
- a server that replies with a TLS alert (modern, non-vulnerable stack);
- a server that completes its handshake flight and only disconnects once the probe payload was received.

The servers are intentionally kept in the test suite and never import anything from the untrusted data directories.
"""

import socketserver
import threading
from enum import Enum

from tls_parser.alert_protocol import TlsAlertRecord, TlsAlertSeverityByte
from tls_parser.record_protocol import TlsVersionEnum as TlsParserVersionEnum

from sslyze import ClientAuthRequirementEnum
from sslyze.server_connectivity import ServerConnectivityInfo, ServerTlsProbingResult, TlsVersionEnum
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


class MockTlsServerBehaviorEnum(Enum):
    """How the mock server reacts once it has received the client's ClientHello."""

    # Never send anything back and never close the socket: the client has to time out
    NEVER_REPLY = "NEVER_REPLY"

    # Close the connection right away, before returning a single TLS record
    CLOSE_BEFORE_ANY_RECORD = "CLOSE_BEFORE_ANY_RECORD"

    # Reply with a TLS alert (handshake_failure) and then close the connection
    REPLY_WITH_ALERT = "REPLY_WITH_ALERT"

    # Send a ServerHelloDone handshake record (completing the server's handshake flight) and only close the
    # connection once the client has sent its probe payload (Heartbleed / early CCS)
    CLOSE_AFTER_HANDSHAKE_FLIGHT = "CLOSE_AFTER_HANDSHAKE_FLIGHT"


# A minimal TLS 1.2 handshake record containing a single ServerHelloDone message
_SERVER_HELLO_DONE_RECORD = bytes.fromhex("16030300040e000000")


def _handle_connection(
    client_socket,
    behavior: MockTlsServerBehaviorEnum,
    alert_description: int,
) -> None:
    # Wait for the client's ClientHello (or the plugin's first payload) so the behavior only triggers once
    # the scanner has actually sent something.
    client_socket.settimeout(10)
    client_socket.recv(4096)

    if behavior == MockTlsServerBehaviorEnum.NEVER_REPLY:
        # Hold the socket open without ever sending anything: the client's recv() has to time out.
        # Keep the connection alive (draining incoming data) longer than the client's own timeout.
        client_socket.settimeout(30)
        while True:
            try:
                if not client_socket.recv(4096):
                    break
            except OSError:
                break

    elif behavior == MockTlsServerBehaviorEnum.CLOSE_BEFORE_ANY_RECORD:
        # Close without having sent a single TLS record
        client_socket.shutdown(socketserver.socket.SHUT_RDWR)

    elif behavior == MockTlsServerBehaviorEnum.REPLY_WITH_ALERT:
        alert_record = TlsAlertRecord.from_parameters(
            tls_version=TlsParserVersionEnum.TLSV1_2,
            alert_severity=TlsAlertSeverityByte.FATAL,
            alert_description=alert_description,
        )
        client_socket.sendall(alert_record.to_bytes())
        client_socket.shutdown(socketserver.socket.SHUT_RDWR)

    elif behavior == MockTlsServerBehaviorEnum.CLOSE_AFTER_HANDSHAKE_FLIGHT:
        # Complete the server's handshake flight, then wait for the probe payload before disconnecting
        client_socket.sendall(_SERVER_HELLO_DONE_RECORD)
        client_socket.settimeout(10)
        try:
            client_socket.recv(4096)
        except OSError:
            pass
        client_socket.shutdown(socketserver.socket.SHUT_RDWR)


class _ThreadingTlsMockServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _MockTlsServer:
    """Threaded TCP server applying the same behavior to every incoming connection."""

    def __init__(self, behavior: MockTlsServerBehaviorEnum, *, alert_description: int = 40) -> None:
        self._behavior = behavior
        self._alert_description = alert_description
        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"

        def _request_handler(request_socket, _address, _server):
            try:
                _handle_connection(request_socket, self._behavior, self._alert_description)
            except OSError:
                pass
            finally:
                request_socket.close()

        self._server = _ThreadingTlsMockServer((self.ip_address, 0), _request_handler)
        self.port = self._server.server_address[1]

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "_MockTlsServer":
        return self

    def __exit__(self, *args) -> bool:
        self.close()
        return False


def build_tls_1_2_server_info(
    mock_server: _MockTlsServer, *, network_timeout: int = 3, network_max_retries: int = 1
) -> ServerConnectivityInfo:
    """Build a ServerConnectivityInfo pointing at a local mock TLS server, claiming TLS 1.2 support.

    The probing result is synthesized (no real connectivity test) so that the Heartbleed/CCS plugins do not
    short-circuit on the TLS 1.3 guard and actually open a connection to the mock server.
    """
    server_location = ServerNetworkLocation(
        hostname=mock_server.hostname, ip_address=mock_server.ip_address, port=mock_server.port
    )
    network_configuration = ServerNetworkConfiguration(
        tls_server_name_indication=mock_server.hostname,
        network_timeout=network_timeout,
        network_max_retries=network_max_retries,
    )
    tls_probing_result = ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
        # OpenSSL-style cipher name accepted by nassl's set_cipher_list()
        cipher_suite_supported="ECDHE-RSA-AES128-GCM-SHA256",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=True,
    )
    return ServerConnectivityInfo(
        server_location=server_location,
        network_configuration=network_configuration,
        tls_probing_result=tls_probing_result,
    )
