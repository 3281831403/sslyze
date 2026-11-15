from typing import List, TYPE_CHECKING, ClassVar

from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo

from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteNotTested,
)
from sslyze.plugins.plugin_base import ScanCommandCliConnector
from sslyze.server_connectivity import TlsVersionEnum

if TYPE_CHECKING:
    from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult


class _CipherSuitesCliConnector(ScanCommandCliConnector["CipherSuitesScanResult", None]):
    _title_in_output: ClassVar[str]

    @classmethod
    def result_to_console_output(cls, result: "CipherSuitesScanResult") -> List[str]:
        result_as_txt = [cls._format_title(cls._title_in_output)]

        tested_cipher_suites_count = len(result.accepted_cipher_suites) + len(result.rejected_cipher_suites)
        untested_cipher_suites_count = len(result.untested_cipher_suites)
        cipher_suites_count = tested_cipher_suites_count + untested_cipher_suites_count

        if not result.accepted_cipher_suites:
            if untested_cipher_suites_count and tested_cipher_suites_count:
                result_as_txt.append(
                    cls._format_subtitle(
                        f"Attempted to connect using {cipher_suites_count} cipher suites;"
                        f" the server rejected all of the {tested_cipher_suites_count} cipher suites that could be"
                        f" tested and {untested_cipher_suites_count} cipher suites could not be tested."
                    )
                )
            elif untested_cipher_suites_count:
                result_as_txt.append(
                    cls._format_subtitle(
                        f"Attempted to connect using {cipher_suites_count} cipher suites;"
                        f" none of them could be tested."
                    )
                )
            else:
                result_as_txt.append(
                    cls._format_subtitle(
                        f"Attempted to connect using {cipher_suites_count} cipher suites;"
                        f" the server rejected all cipher suites."
                    )
                )
            result_as_txt.extend(_format_untested_cipher_suites(result.untested_cipher_suites))
            return result_as_txt

        # Display all cipher suites that were accepted
        result_as_txt.append(cls._format_subtitle(f"Attempted to connect using {cipher_suites_count} cipher suites."))
        result_as_txt.append("")
        result_as_txt.append(
            cls._format_subtitle(
                f"The server accepted the following {len(result.accepted_cipher_suites)} cipher suites:"
            )
        )
        for accepted_cipher in result.accepted_cipher_suites:
            result_as_txt.append(_format_accepted_cipher_suite(accepted_cipher))
        result_as_txt.append("")
        result_as_txt.extend(_format_untested_cipher_suites(result.untested_cipher_suites))

        # Display some general comments about the cipher suite configuration
        # These comments only apply to TLS versions below 1.3 because TLS 1.3 removed "bad" cipher suites
        if result.tls_version_used.value < TlsVersionEnum.TLS_1_3.value:
            result_as_txt.append(
                cls._format_subtitle("The group of cipher suites supported by the server has the following properties:")
            )

            # Forward secrecy
            supports_forward_secrecy = False
            for accepted_cipher in result.accepted_cipher_suites:
                if "_DHE_" in accepted_cipher.cipher_suite.name or "_ECDHE_" in accepted_cipher.cipher_suite.name:
                    supports_forward_secrecy = True
                    break

            result_as_txt.append(
                cls._format_field(
                    "Forward Secrecy", "OK - Supported" if supports_forward_secrecy else "INSECURE - Not Supported"
                )
            )

            # Insecure RC4 cipher suites
            supports_rc4 = False
            for accepted_cipher in result.accepted_cipher_suites:
                if "_RC4_" in accepted_cipher.cipher_suite.name:
                    supports_rc4 = True
                    break
            result_as_txt.append(
                cls._format_field(
                    "Legacy RC4 Algorithm", "INSECURE - Supported" if supports_rc4 else "OK - Not Supported"
                )
            )
            result_as_txt.append("")

        return result_as_txt


def _format_untested_cipher_suites(untested_cipher_suites: List[CipherSuiteNotTested]) -> List[str]:
    if not untested_cipher_suites:
        return []

    result_as_txt = [
        _CipherSuitesCliConnector._format_subtitle(
            f"The following {len(untested_cipher_suites)} cipher suites could not be tested because the TLS handshake"
            " timed out:"
        )
    ]
    for untested_cipher in untested_cipher_suites:
        result_as_txt.append(f"        {untested_cipher.cipher_suite.name}")
    result_as_txt.append("")

    return result_as_txt


def _format_accepted_cipher_suite(accepted_cipher: CipherSuiteAcceptedByServer) -> str:
    eph_key = accepted_cipher.ephemeral_key
    if isinstance(eph_key, EcDhEphemeralKeyInfo):
        dh_info = f"ECDH: {eph_key.curve_name} ({eph_key.size} bits)"
    elif isinstance(eph_key, DhEphemeralKeyInfo):
        dh_info = f"DH ({eph_key.size} bits)"
    else:
        dh_info = ""

    return f"        {accepted_cipher.cipher_suite.name:<50}{accepted_cipher.cipher_suite.key_size:<10}{dh_info:<15}"
