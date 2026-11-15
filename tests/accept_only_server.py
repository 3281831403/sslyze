import socket
import threading
from types import TracebackType
from typing import List, Optional, Type


class AcceptOnlyServer:
    """A TCP server that accepts connections but never sends any data back.

    This simulates servers that are reachable over TCP but never reply to the TLS ClientHello, for example because
    a firewall or a load balancer silently drops TLS records. In that case the TLS handshake times out, and SSLyze
    cannot tell whether the server supports a given TLS version/cipher suite or not.
    """

    def __init__(self) -> None:
        self._listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listening_socket.bind(("127.0.0.1", 0))
        self._listening_socket.listen(100)
        self._connected_sockets: List[socket.socket] = []
        self._accept_thread: Optional[threading.Thread] = None
        self._should_stop = False

        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"
        self.port = self._listening_socket.getsockname()[1]

    @property
    def accepted_connections_count(self) -> int:
        return len(self._connected_sockets)

    def _accept_connections(self) -> None:
        while not self._should_stop:
            try:
                connected_socket, _ = self._listening_socket.accept()
            except socket.timeout:
                # Periodically check self._should_stop; closing the listening socket does not reliably wake up a
                # thread blocked in accept() on all platforms
                continue
            except OSError:
                # The listening socket was closed
                return
            # Keep the socket open but never send anything back, so that the client's TLS handshake times out
            self._connected_sockets.append(connected_socket)

    def __enter__(self) -> "AcceptOnlyServer":
        # Use a timeout so that the accept thread can be reliably stopped
        self._listening_socket.settimeout(0.1)
        self._accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._accept_thread.start()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self._should_stop = True
        if self._accept_thread:
            self._accept_thread.join()
        self._listening_socket.close()
        for connected_socket in self._connected_sockets:
            connected_socket.close()
