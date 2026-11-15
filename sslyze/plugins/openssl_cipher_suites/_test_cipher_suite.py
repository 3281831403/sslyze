from dataclasses import dataclass
from typing import Optional, Union

from nassl.ephemeral_key_info import EphemeralKeyInfo
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, SslClient, BaseSslClient

from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    TlsHandshakeTimedOut,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.plugins.openssl_cipher_suites._tls12_workaround import WorkaroundForTls12ForCipherSuites


@dataclass(frozen=True)
class CipherSuiteAcceptedByServer:
    """
    ephemeral_key: The ephemeral key negotiated with the server when using (EC) DH cipher suites. None if the cipher
        suite does not use ephemeral keys or if the ephemeral key could not be retrieved.
    """

    cipher_suite: CipherSuite
    ephemeral_key: Optional[EphemeralKeyInfo]


@dataclass(frozen=True)
class CipherSuiteRejectedByServer:
    cipher_suite: CipherSuite
    error_message: str


@dataclass(frozen=True)
class CipherSuiteNotTested:
    """The cipher suite could not be tested, as no conclusion could be reached after retrying.

    This is different from CipherSuiteRejectedByServer: the server did not explicitly reject the cipher suite; instead
    the TLS handshake kept timing out, which means it is unknown whether the server supports this cipher suite or not.

    Attributes:
        cipher_suite: The cipher suite that SSLyze was unable to test.
        error_message: The error message from the last failed attempt at testing this cipher suite.
    """

    cipher_suite: CipherSuite
    error_message: str


_CipherSuiteTestResult = Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer, CipherSuiteNotTested]


def connect_with_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, cipher_suite: CipherSuite
) -> _CipherSuiteTestResult:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified."""
    requires_legacy_openssl = True
    if tls_version == TlsVersionEnum.TLS_1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_suite.openssl_name)
    elif tls_version == TlsVersionEnum.TLS_1_3:
        requires_legacy_openssl = False

    # If the TLS handshake times out, we cannot tell whether the server rejected the cipher suite or whether the
    # timeout was caused by a network issue; retry a few times before giving up.
    # This matches the retry behavior used when establishing the underlying network connection.
    max_attempts_nb = server_connectivity_info.network_configuration.network_max_retries
    if max_attempts_nb < 1:
        max_attempts_nb = 1

    last_timeout_error: Optional[TlsHandshakeTimedOut] = None
    for _ in range(max_attempts_nb):
        # A new connection is needed for every attempt
        ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
            override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
        )

        # Always only enable the cipher suite to test, including on retries; otherwise OpenSSL would fall back to its
        # default cipher list and we could end up testing a different cipher suite than the one we're trying to test
        _set_cipher_suite_string(tls_version, cipher_suite.openssl_name, ssl_connection.ssl_client)

        ephemeral_key = None
        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

        except ServerTlsConfigurationNotSupported:
            # SSLyze rejected the handshake because the server's DH config was too insecure; this means the
            # cipher suite is actually supported
            pass

        except ClientCertificateRequested:
            # When the handshake failed due to ClientCertificateRequested
            ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()
            pass

        except ServerRejectedTlsHandshake as e:
            # The server explicitly rejected the cipher suite; do not retry
            return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=e.error_message)

        except TlsHandshakeTimedOut as e:
            # Retry: we cannot tell yet whether the server rejected the cipher suite or whether the timeout was caused
            # by a network issue. Amazon Cloudfront with TLS 1.3 and servers that silently drop TLS records trigger this.
            last_timeout_error = e
            continue

        finally:
            ssl_connection.close()

        return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=ephemeral_key)

    # All attempts timed out: we could NOT test this cipher suite
    assert last_timeout_error is not None
    return CipherSuiteNotTested(cipher_suite=cipher_suite, error_message=last_timeout_error.error_message)


def _set_cipher_suite_string(tls_version: TlsVersionEnum, cipher_suite_str: str, ssl_client: BaseSslClient) -> None:
    # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
    if isinstance(ssl_client, SslClient):
        # With the modern OpenSSL client we have to manage TLS 1.3-specific cipher functions
        if tls_version == TlsVersionEnum.TLS_1_3:
            ssl_client.set_ciphersuites(cipher_suite_str)  # TLS 1.3 method
        else:
            ssl_client.set_cipher_list(cipher_suite_str)  # Legacy method
    elif isinstance(ssl_client, LegacySslClient):
        # With the legacy OpenSSL client, nothing special to do
        ssl_client.set_cipher_list(cipher_suite_str)
    else:
        raise RuntimeError("Should never happen")
