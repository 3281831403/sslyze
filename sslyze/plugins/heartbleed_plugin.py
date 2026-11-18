import socket
import types
from dataclasses import dataclass
from typing import List, Optional

import tls_parser.record_protocol
from nassl._nassl import WantReadError
from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.exceptions import NotEnoughData, UnknownTlsVersionByte
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte
from tls_parser.heartbeat_protocol import TlsHeartbeatRequestRecord
from tls_parser.parser import TlsRecordParser

from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandCliConnector,
    ScanCommandExtraArgument,
    ScanCommandImplementation,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanJob,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class HeartbleedScanResult(ScanCommandResult):
    """The result of testing a server for the OpenSSL Heartbleed vulnerability.

    Attributes:
        is_vulnerable_to_heartbleed: True if the server is vulnerable to the Heartbleed attack.
    """

    is_vulnerable_to_heartbleed: bool


class HeartbleedScanResultAsJson(BaseModelWithOrmModeAndForbid):
    is_vulnerable_to_heartbleed: bool


class HeartbleedScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[HeartbleedScanResultAsJson]


class _HeartbleedCliConnector(ScanCommandCliConnector[HeartbleedScanResult, None]):
    _cli_option = "heartbleed"
    _cli_description = "Test a server for the OpenSSL Heartbleed vulnerability."

    @classmethod
    def result_to_console_output(cls, result: HeartbleedScanResult) -> List[str]:
        result_as_txt = [cls._format_title("OpenSSL Heartbleed")]
        heartbleed_txt = (
            "VULNERABLE - Server is vulnerable to Heartbleed"
            if result.is_vulnerable_to_heartbleed
            else "OK - Not vulnerable to Heartbleed"
        )
        result_as_txt.append(cls._format_field("", heartbleed_txt))
        return result_as_txt


class HeartbleedImplementation(ScanCommandImplementation[HeartbleedScanResult, None]):
    """Test a server for the OpenSSL Heartbleed vulnerability."""

    cli_connector_cls = _HeartbleedCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_heartbleed, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> HeartbleedScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return HeartbleedScanResult(is_vulnerable_to_heartbleed=scan_job_results[0].get_result())


def _test_heartbleed(server_info: ServerConnectivityInfo) -> bool:
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        # The server uses a recent version of OpenSSL and it cannot be vulnerable to Heartbleed
        return False

    # Disable SNI for this check because some legacy servers don't support sending the heartbleed payload and SNI
    # See https://github.com/nabla-c0d3/sslyze/issues/202
    ssl_connection = server_info.get_preconfigured_tls_connection(should_enable_server_name_indication=False)

    # Replace nassl.sslClient.do_handshake() with a heartbleed checking SSL handshake so that all the SSLyze options
    # (startTLS, proxy, etc.) still work
    ssl_connection.ssl_client.do_handshake = types.MethodType(  # type: ignore
        _do_handshake_with_heartbleed(server_info), ssl_connection.ssl_client
    )

    is_vulnerable_to_heartbleed = False
    try:
        # Start the SSL handshake
        ssl_connection.connect()
    except _VulnerableToHeartbleed:
        # The test was completed and the server is vulnerable
        is_vulnerable_to_heartbleed = True
    except _NotVulnerableToHeartbleed:
        # The test was completed and the server is NOT vulnerable
        pass
    finally:
        ssl_connection.close()

    return is_vulnerable_to_heartbleed


class _VulnerableToHeartbleed(Exception):
    """Exception to raise during the handshake to hijack the flow and test for Heartbleed."""


class _NotVulnerableToHeartbleed(Exception):
    """Exception to raise during the handshake to hijack the flow and test for Heartbleed."""


def _raise_heartbleed_connection_error(server_info: ServerConnectivityInfo, error_message: str) -> None:
    """Report a connectivity failure when the Heartbleed test could not be completed.

    A "not vulnerable" conclusion is only valid if the server actually replied - either with a TLS alert, or by
    sending its full handshake flight before reacting to the payload. If the connection was dropped or timed out
    before any TLS record was received (for example because a middlebox silently reset the connection), the test is
    inconclusive and must be reported as a connectivity issue with no result, rather than as "not vulnerable".
    """
    raise ServerRejectedTlsHandshake(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message=error_message,
    )


def _do_handshake_with_heartbleed(server_info: ServerConnectivityInfo):  # type: ignore
    """Build a modified do_handshake() that sends a heartbleed payload and interprets the response."""

    def _do_handshake(self):  # type: ignore
        try:
            # Start the handshake using nassl - will throw WantReadError right away
            self._ssl.do_handshake()
        except WantReadError:
            # Send the Client Hello
            len_to_read = self._network_bio.pending()
            while len_to_read:
                # Get the data from the SSL engine
                handshake_data_out = self._network_bio.read(len_to_read)
                # Send it to the peer
                self._sock.send(handshake_data_out)
                len_to_read = self._network_bio.pending()

        # Build the heartbleed payload - based on
        # https://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server/
        payload = TlsHeartbeatRequestRecord.from_parameters(
            tls_version=tls_parser.record_protocol.TlsVersionEnum[self._ssl_version.name],
            heartbeat_data=b"\x01" * 16381,
        ).to_bytes()

        payload += TlsHeartbeatRequestRecord.from_parameters(
            tls_version=tls_parser.record_protocol.TlsVersionEnum[self._ssl_version.name],
            heartbeat_data=b"\x01\x00\x00",
        ).to_bytes()

        # Send the payload
        self._sock.send(payload)

        # Retrieve the server's response - directly read the underlying network socket
        # Retrieve data until we get to the ServerHelloDone
        # The server may send back a ServerHello, an Alert, a CertificateRequest or may just close the connection.
        # Track whether the server ever sent back a TLS record: if the connection dies before any record is
        # received, the test is inconclusive and has to be reported as a connectivity error instead of a
        # "not vulnerable" false negative (middleboxes silently dropping the connection, unresponsive servers, ...).
        did_receive_any_tls_record = False
        did_receive_hello_done = False
        remaining_bytes = b""
        while not did_receive_hello_done:
            try:
                tls_record, len_consumed = TlsRecordParser.parse_bytes(remaining_bytes)
                remaining_bytes = remaining_bytes[len_consumed::]
            except UnknownTlsVersionByte as e:
                # Workaround for Amazon Cloudfront; see https://github.com/nabla-c0d3/sslyze/issues/437
                if e.record_type == tls_parser.record_protocol.TlsRecordTypeByte.ALERT:
                    # Server returned a (badly-formatted) TLS alert because it requires SNI
                    # Hence the server uses a modern TLS stack and is not vulnerable
                    raise _NotVulnerableToHeartbleed()
                else:
                    raise
            except NotEnoughData:
                # Try to get more data
                try:
                    raw_ssl_bytes = self._sock.recv(16381)
                except socket.timeout:
                    # The server stopped responding; no conclusion can be drawn
                    _raise_heartbleed_connection_error(
                        server_info, "Server timed out before returning a response during the Heartbleed check"
                    )
                except socket.error:
                    # The server closed/reset the connection
                    if did_receive_any_tls_record:
                        # It had already sent back a TLS record (handshake flight or alert) before closing the
                        # connection upon receiving the Heartbleed payload: the test was completed
                        raise _NotVulnerableToHeartbleed()
                    # The connection was dropped before the server sent a single TLS record: inconclusive
                    _raise_heartbleed_connection_error(
                        server_info,
                        "Server closed the connection before sending any TLS record during the Heartbleed check",
                    )

                if not raw_ssl_bytes:
                    # The server closed the connection (EOF)
                    if did_receive_any_tls_record:
                        # It had already returned its handshake flight before closing upon receiving the payload:
                        # the test was completed and the server is not vulnerable
                        raise _NotVulnerableToHeartbleed()
                    # No TLS record was ever received: the test is inconclusive
                    _raise_heartbleed_connection_error(
                        server_info,
                        "Server closed the connection before sending any TLS record during the Heartbleed check",
                    )

                did_receive_any_tls_record = True
                remaining_bytes = remaining_bytes + raw_ssl_bytes
                continue

            did_receive_any_tls_record = True
            if isinstance(tls_record, TlsHandshakeRecord):
                # Does the record contain a ServerDone message?
                for handshake_message in tls_record.subprotocol_messages:
                    if handshake_message.handshake_type == TlsHandshakeTypeByte.SERVER_DONE:
                        did_receive_hello_done = True
                        break
                # If not, it could be a ServerHello, Certificate or a CertificateRequest if the server requires
                # client auth
            elif isinstance(tls_record, TlsAlertRecord):
                # Server returned a TLS alert
                break
            else:
                raise ValueError("Unknown record? Type {}".format(tls_record.header.type))

        is_vulnerable_to_heartbleed = False
        if did_receive_hello_done:
            expected_heartbleed_payload = b"\x01" * 10
            if expected_heartbleed_payload in remaining_bytes:
                # Server replied with our heartbeat payload
                is_vulnerable_to_heartbleed = True
            else:
                try:
                    raw_ssl_bytes = self._sock.recv(16381)
                except socket.timeout:
                    # The server completed its handshake flight but never answered the heartbeat request:
                    # the test is inconclusive
                    _raise_heartbleed_connection_error(
                        server_info, "Server timed out before returning a response during the Heartbleed check"
                    )
                except socket.error:
                    # Server closed the connection after receiving the heartbleed payload; it had already completed
                    # its handshake flight so the test was completed and the server is not vulnerable
                    raise _NotVulnerableToHeartbleed()

                if expected_heartbleed_payload in raw_ssl_bytes:
                    # Server replied with our heartbeat payload
                    is_vulnerable_to_heartbleed = True

        if is_vulnerable_to_heartbleed:
            raise _VulnerableToHeartbleed()
        else:
            raise _NotVulnerableToHeartbleed()

    return _do_handshake
