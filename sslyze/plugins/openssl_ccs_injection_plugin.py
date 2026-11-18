import socket
import types
from dataclasses import dataclass
from typing import List, Optional

import tls_parser.tls_version
from nassl._nassl import WantReadError
from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.application_data_protocol import TlsApplicationDataRecord
from tls_parser.change_cipher_spec_protocol import TlsChangeCipherSpecRecord
from tls_parser.exceptions import NotEnoughData, UnknownTlsVersionByte
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte
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
class OpenSslCcsInjectionScanResult(ScanCommandResult):
    """The result of testing a server for the OpenSSL CCS Injection vulnerability (CVE-2014-0224).

    Attributes:
        is_vulnerable_to_ccs_injection: True if the server is vulnerable to the OpenSSL CCS Injection vulnerability.
    """

    is_vulnerable_to_ccs_injection: bool


class OpenSslCcsInjectionScanResultAsJson(BaseModelWithOrmModeAndForbid):
    is_vulnerable_to_ccs_injection: bool


class OpenSslCcsInjectionScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[OpenSslCcsInjectionScanResultAsJson]


class _OpenSslCcsInjectionCliConnector(ScanCommandCliConnector[OpenSslCcsInjectionScanResult, None]):
    _cli_option = "openssl_ccs"
    _cli_description = "Test a server for the OpenSSL CCS Injection vulnerability (CVE-2014-0224)."

    @classmethod
    def result_to_console_output(cls, result: OpenSslCcsInjectionScanResult) -> List[str]:
        result_txt = [cls._format_title("OpenSSL CCS Injection")]
        ccs_text = (
            "VULNERABLE - Server is vulnerable to OpenSSL CCS injection"
            if result.is_vulnerable_to_ccs_injection
            else "OK - Not vulnerable to OpenSSL CCS injection"
        )
        result_txt.append(cls._format_field("", ccs_text))
        return result_txt


class OpenSslCcsInjectionImplementation(ScanCommandImplementation[OpenSslCcsInjectionScanResult, None]):
    """Test a server for the OpenSSL CCS Injection vulnerability (CVE-2014-0224)."""

    cli_connector_cls = _OpenSslCcsInjectionCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_for_ccs_injection, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> OpenSslCcsInjectionScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return OpenSslCcsInjectionScanResult(is_vulnerable_to_ccs_injection=scan_job_results[0].get_result())


def _test_for_ccs_injection(server_info: ServerConnectivityInfo) -> bool:
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        # The server uses a recent version of OpenSSL and it cannot be vulnerable to CCS Injection
        return False

    # Disable SNI for this check because some legacy servers don't support sending the CCS payload and SNI
    # See https://github.com/nabla-c0d3/sslyze/issues/202
    ssl_connection = server_info.get_preconfigured_tls_connection(should_enable_server_name_indication=False)

    # Replace nassl.sslClient.do_handshake() with a CCS checking SSL handshake so that all the SSLyze options
    # (startTLS, proxy, etc.) still work
    ssl_connection.ssl_client.do_handshake = types.MethodType(  # type: ignore
        _do_handshake_with_ccs_injection(server_info), ssl_connection.ssl_client
    )

    is_vulnerable = False
    try:
        # Start the SSL handshake
        ssl_connection.connect()
    except _VulnerableToCcsInjection:
        # The test was completed and the server is vulnerable
        is_vulnerable = True
    except _NotVulnerableToCcsInjection:
        # The test was completed and the server is NOT vulnerable
        pass
    finally:
        ssl_connection.close()

    return is_vulnerable


class _VulnerableToCcsInjection(Exception):
    """Exception to raise during the handshake to hijack the flow and test for CCS."""


class _NotVulnerableToCcsInjection(Exception):
    """Exception to raise during the handshake to hijack the flow and test for CCS."""


def _raise_ccs_connection_error(server_info: ServerConnectivityInfo, error_message: str) -> None:
    """Report a connectivity failure when the CCS injection test could not be completed.

    A "not vulnerable" conclusion is only valid if the server actually replied - either with a TLS alert, or by
    receiving the full early-CCS payload before closing the connection. If the connection was dropped or timed out
    before any TLS record was received (for example because a middlebox silently reset the connection), the test is
    inconclusive and must be reported as a connectivity issue with no result, rather than as "not vulnerable".
    """
    raise ServerRejectedTlsHandshake(
        server_location=server_info.server_location,
        network_configuration=server_info.network_configuration,
        error_message=error_message,
    )


def _do_handshake_with_ccs_injection(server_info: ServerConnectivityInfo):  # type: ignore
    """Build a modified do_handshake() that sends a CCS injection payload and interprets the response."""

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

        # Retrieve the server's response - directly read the underlying network socket
        # Retrieve data until we get to the ServerHelloDone
        # The server may send back a ServerHello, an Alert or a CertificateRequest first.
        # Track whether the server ever sent back a TLS record: if the connection dies before any record is
        # received, the test is inconclusive and has to be reported as a connectivity error instead of a
        # "not vulnerable" false negative (middleboxes silently dropping the connection, unresponsive servers, ...).
        did_receive_any_tls_record = False
        did_receive_hello_done = False
        did_receive_alert = False
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
                    raise _NotVulnerableToCcsInjection()
                else:
                    raise
            except NotEnoughData:
                # Try to get more data
                try:
                    raw_ssl_bytes = self._sock.recv(16381)
                except socket.timeout:
                    # The server stopped responding; no conclusion can be drawn
                    _raise_ccs_connection_error(
                        server_info, "Server timed out before returning a response during the CCS injection check"
                    )
                except ConnectionError:
                    # The server closed/reset the connection before sending any (more) TLS record
                    if did_receive_any_tls_record:
                        break
                    # The connection was dropped before the server sent a single TLS record: inconclusive
                    _raise_ccs_connection_error(
                        server_info,
                        "Server closed the connection before sending any TLS record during the CCS injection check",
                    )

                if not raw_ssl_bytes:
                    # EOF: the server closed the connection
                    if did_receive_any_tls_record:
                        break
                    # No TLS record was ever received: the test is inconclusive
                    _raise_ccs_connection_error(
                        server_info,
                        "Server closed the connection before sending any TLS record during the CCS injection check",
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
                did_receive_alert = True
                break
            else:
                raise ValueError("Unknown record? Type {}".format(tls_record.header.type))

        if not did_receive_hello_done:
            if did_receive_alert:
                # The server rejected the ClientHello with a TLS alert: it runs a modern, non-vulnerable stack
                raise _NotVulnerableToCcsInjection()
            # The connection was closed/reset after the server had sent at least one TLS record but before
            # completing its handshake flight; the early CCS payload was never sent so the test is inconclusive
            _raise_ccs_connection_error(
                server_info,
                "Server closed the connection before completing its TLS handshake during the CCS injection check",
            )

        # Send an early CCS record - this should be rejected by the server
        payload = TlsChangeCipherSpecRecord.from_parameters(
            tls_version=tls_parser.tls_version.TlsVersionEnum[self._ssl_version.name]
        ).to_bytes()
        self._sock.send(payload)

        # Send an early application data record which should be ignored by the server
        app_data_record = TlsApplicationDataRecord.from_parameters(
            tls_version=tls_parser.tls_version.TlsVersionEnum[self._ssl_version.name], application_data=b"\x00\x00"
        )
        self._sock.send(app_data_record.to_bytes())

        # Check if an alert was sent back
        while True:
            try:
                tls_record, len_consumed = TlsRecordParser.parse_bytes(remaining_bytes)
                remaining_bytes = remaining_bytes[len_consumed::]
            except NotEnoughData:
                # Try to get more data
                try:
                    raw_ssl_bytes = self._sock.recv(16381)
                    if not raw_ssl_bytes:
                        # EOF: the server received the early CCS payload and then closed the connection, which is
                        # how a non-vulnerable stack rejects the invalid record
                        raise _NotVulnerableToCcsInjection()
                except socket.timeout:
                    # The server stopped responding after receiving the CCS payload: the test is inconclusive
                    _raise_ccs_connection_error(
                        server_info, "Server timed out before returning a response during the CCS injection check"
                    )
                except socket.error:
                    # Server closed the connection after receiving the CCS payload: the test was completed and the
                    # server is not vulnerable
                    raise _NotVulnerableToCcsInjection()

                remaining_bytes = remaining_bytes + raw_ssl_bytes
                continue

            if isinstance(tls_record, TlsAlertRecord):
                # Server returned a TLS alert but which one?
                if tls_record.alert_description == 0x14:
                    # BAD_RECORD_MAC: This means that the server actually tried to decrypt our early application data
                    # record instead of ignoring it; server is vulnerable
                    raise _VulnerableToCcsInjection()

                # Any other alert means that the server rejected the early CCS record
                raise _NotVulnerableToCcsInjection()
            else:
                break

        raise _NotVulnerableToCcsInjection()

    return _do_handshake
