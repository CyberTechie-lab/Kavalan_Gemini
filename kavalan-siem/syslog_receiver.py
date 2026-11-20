"""
syslog_receiver.py - Lightweight Syslog Receiver for Kavalan SIEM

Listens for incoming Syslog streams from firewalls, network appliances, and routers:
  - UDP port 514 / 1514 (RFC 3164 BSD & RFC 5424 IETF)
  - TCP port 514 / 1514 with line-delimiters
  - Decodes and normalizes directly to CEMEvent
  - Forwards normalized event batches to Kavalan Manager on port 8910
"""

import argparse
import json
import socket
import sys
import threading
import time
import urllib.request
from typing import List, Optional

from cem import CEMEvent
from manager.decoders.decoders import DecoderPipeline


class SyslogReceiver:
    """Multi-protocol UDP/TCP syslog listener daemon."""

    def __init__(self, port: int = 1514, manager_url: str = "http://127.0.0.1:8910"):
        self.port = port
        self.manager_url = manager_url.rstrip("/")
        self.decoder_pipeline = DecoderPipeline()
        self.stop_event = threading.Event()
        self.buffer: List[dict] = []
        self.lock = threading.Lock()
        self.events_received = 0

    def start(self, run_in_background: bool = True) -> None:
        udp_thread = threading.Thread(target=self._run_udp_server, daemon=True, name="SyslogUDP")
        tcp_thread = threading.Thread(target=self._run_tcp_server, daemon=True, name="SyslogTCP")
        flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="SyslogFlusher")

        udp_thread.start()
        tcp_thread.start()
        flush_thread.start()

        if not run_in_background:
            try:
                while not self.stop_event.is_set():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        self.stop_event.set()

    def _process_line(self, line: str, client_ip: str) -> None:
        line = line.strip()
        if not line:
            return
        self.events_received += 1
        event = self.decoder_pipeline.decode_line(line, host=f"net-{client_ip}")
        if event:
            with self.lock:
                self.buffer.append(event.to_dict())

    def _run_udp_server(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", self.port))
            sock.settimeout(1.0)
        except Exception as e:
            # Try fallback port if privileged port denied
            if self.port == 514:
                try:
                    self.port = 1514
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(("0.0.0.0", self.port))
                    sock.settimeout(1.0)
                except Exception:
                    return
            else:
                return

        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(8192)
                text = data.decode("utf-8", errors="replace")
                self._process_line(text, addr[0])
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()

    def _run_tcp_server(self) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen(10)
            server.settimeout(1.0)
        except Exception:
            return

        while not self.stop_event.is_set():
            try:
                conn, addr = server.accept()
                threading.Thread(target=self._handle_tcp_client, args=(conn, addr[0]), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        server.close()

    def _handle_tcp_client(self, conn: socket.socket, client_ip: str) -> None:
        buf = ""
        conn.settimeout(5.0)
        while not self.stop_event.is_set():
            try:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    self._process_line(line, client_ip)
            except socket.timeout:
                continue
            except Exception:
                break
        conn.close()

    def _flush_loop(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(2.0)
            with self.lock:
                if not self.buffer:
                    continue
                batch = list(self.buffer[:100])
                del self.buffer[:100]

            try:
                payload = json.dumps({"events": batch}).encode("utf-8")
                req = urllib.request.Request(
                    f"{self.manager_url}/api/ingest",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    pass
            except Exception:
                # Re-queue on failure if buffer not full
                with self.lock:
                    if len(self.buffer) < 500:
                        self.buffer.extend(batch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kavalan Syslog Receiver")
    parser.add_argument("--port", type=int, default=1514, help="Port to bind UDP/TCP (default: 1514)")
    parser.add_argument("--manager", default="http://127.0.0.1:8910", help="Manager API URL")
    args = parser.parse_args()

    print(f"[*] Starting Kavalan Syslog Receiver on UDP/TCP port {args.port}...")
    rcv = SyslogReceiver(port=args.port, manager_url=args.manager)
    rcv.start(run_in_background=False)
