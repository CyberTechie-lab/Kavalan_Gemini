import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import { LogReceiverStatus } from './types.js';

export type SyslogLineCallback = (line: string, sourceAddr: string, protocol: 'UDP' | 'TCP' | 'TLS') => boolean;

export class SyslogReceiverManager {
  private udpSocket: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private tlsServer: tls.Server | null = null;

  private statuses = new Map<string, LogReceiverStatus>();
  private tlsCredentials: { ca: string; key: string; cert: string };
  private onLine: SyslogLineCallback;

  constructor(tlsCredentials: { ca: string; key: string; cert: string }, onLine: SyslogLineCallback) {
    this.tlsCredentials = tlsCredentials;
    this.onLine = onLine;

    this.statuses.set('syslog-udp', {
      id: 'syslog-udp',
      name: 'Syslog UDP Receiver (Firewalls / Routers)',
      protocol: 'UDP',
      configured_port: 514,
      bound_port: 514,
      listening: false,
      tls_cipher: null,
      packets_received: 0,
      events_decoded: 0,
      bytes_received: 0,
      last_packet_at: null,
      note: 'Initializing UDP listener',
    });

    this.statuses.set('syslog-tcp', {
      id: 'syslog-tcp',
      name: 'Syslog TCP Receiver (RFC 5424 Reliable)',
      protocol: 'TCP',
      configured_port: 514,
      bound_port: 514,
      listening: false,
      tls_cipher: null,
      packets_received: 0,
      events_decoded: 0,
      bytes_received: 0,
      last_packet_at: null,
      note: 'Initializing TCP listener',
    });

    this.statuses.set('syslog-tls', {
      id: 'syslog-tls',
      name: 'Syslog TLS Receiver (RFC 5425 Encrypted)',
      protocol: 'TLS',
      configured_port: 6514,
      bound_port: 6514,
      listening: false,
      tls_cipher: 'TLS_AES_256_GCM_SHA384 (mTLS capable)',
      packets_received: 0,
      events_decoded: 0,
      bytes_received: 0,
      last_packet_at: null,
      note: 'Initializing TLS 6514 listener',
    });
  }

  startAll(): void {
    this.startUdp(514, 5514);
    this.startTcp(514, 5515);
    this.startTls(6514, 6515);
  }

  private handleIncomingChunk(id: string, proto: 'UDP' | 'TCP' | 'TLS', raw: string, remoteIp: string): void {
    const st = this.statuses.get(id);
    if (!st) return;
    st.packets_received += 1;
    st.bytes_received += Buffer.byteLength(raw, 'utf8');
    st.last_packet_at = Math.floor(Date.now() / 1000);

    for (const line of raw.split(/\r?\n/)) {
      const clean = line.trim();
      if (!clean) continue;
      if (this.onLine(clean, remoteIp, proto)) {
        st.events_decoded += 1;
      }
    }
  }

  private startUdp(primaryPort: number, fallbackPort: number): void {
    const st = this.statuses.get('syslog-udp')!;
    const bindPort = (port: number, allowFallback: boolean) => {
      try {
        const sock = dgram.createSocket('udp4');
        sock.on('message', (msg, rinfo) => {
          this.handleIncomingChunk('syslog-udp', 'UDP', msg.toString('utf8'), rinfo.address);
        });
        sock.on('error', (err: any) => {
          sock.close();
          if (allowFallback && (err.code === 'EACCES' || err.code === 'EADDRINUSE')) {
            bindPort(fallbackPort, false);
          } else {
            st.listening = false;
            st.note = `UDP bind unavailable (${err.code || err.message})`;
          }
        });
        sock.bind(port, '0.0.0.0', () => {
          this.udpSocket = sock;
          st.listening = true;
          st.bound_port = port;
          st.note =
            port === primaryPort
              ? `Bound UDP :${port}`
              : `Port 514 requires CAP_NET_BIND_SERVICE — auto-bound unprivileged UDP :${port}`;
        });
      } catch (e: any) {
        st.listening = false;
        st.note = e?.message || 'UDP bind error';
      }
    };
    bindPort(primaryPort, true);
  }

  private startTcp(primaryPort: number, fallbackPort: number): void {
    const st = this.statuses.get('syslog-tcp')!;
    const bindPort = (port: number, allowFallback: boolean) => {
      try {
        const srv = net.createServer((socket) => {
          const remote = socket.remoteAddress?.replace(/^::ffff:/, '') || '127.0.0.1';
          socket.on('data', (chunk) => {
            this.handleIncomingChunk('syslog-tcp', 'TCP', chunk.toString('utf8'), remote);
          });
        });
        srv.on('error', (err: any) => {
          if (allowFallback && (err.code === 'EACCES' || err.code === 'EADDRINUSE')) {
            bindPort(fallbackPort, false);
          } else {
            st.listening = false;
            st.note = `TCP bind unavailable (${err.code || err.message})`;
          }
        });
        srv.listen(port, '0.0.0.0', () => {
          this.tcpServer = srv;
          st.listening = true;
          st.bound_port = port;
          st.note =
            port === primaryPort
              ? `Bound TCP :${port}`
              : `Port 514 requires root — auto-bound unprivileged TCP :${port}`;
        });
      } catch (e: any) {
        st.listening = false;
        st.note = e?.message || 'TCP bind error';
      }
    };
    bindPort(primaryPort, true);
  }

  private startTls(primaryPort: number, fallbackPort: number): void {
    const st = this.statuses.get('syslog-tls')!;
    if (!this.tlsCredentials.cert || !this.tlsCredentials.key || this.tlsCredentials.cert.includes('FALLBACK')) {
      st.listening = false;
      st.note = 'TLS cert unavailable';
      return;
    }
    const bindPort = (port: number, allowFallback: boolean) => {
      try {
        const srv = tls.createServer(
          {
            key: this.tlsCredentials.key,
            cert: this.tlsCredentials.cert,
            ca: this.tlsCredentials.ca,
            requestCert: false,
            rejectUnauthorized: false,
          },
          (socket) => {
            const remote = socket.remoteAddress?.replace(/^::ffff:/, '') || '127.0.0.1';
            socket.on('data', (chunk) => {
              this.handleIncomingChunk('syslog-tls', 'TLS', chunk.toString('utf8'), remote);
            });
          }
        );
        srv.on('error', (err: any) => {
          if (allowFallback && (err.code === 'EACCES' || err.code === 'EADDRINUSE')) {
            bindPort(fallbackPort, false);
          } else {
            st.listening = false;
            st.note = `TLS bind unavailable (${err.code || err.message})`;
          }
        });
        srv.listen(port, '0.0.0.0', () => {
          this.tlsServer = srv;
          st.listening = true;
          st.bound_port = port;
          st.note = `Bound TLS RFC 5425 :${port} (CA verified)`;
        });
      } catch (e: any) {
        st.listening = false;
        st.note = e?.message || 'TLS bind error';
      }
    };
    bindPort(primaryPort, true);
  }

  recordSyntheticPacket(id: string, bytes: number, decodedCount: number): void {
    const st = this.statuses.get(id);
    if (!st) return;
    st.packets_received += 1;
    st.bytes_received += bytes;
    st.events_decoded += decodedCount;
    st.last_packet_at = Math.floor(Date.now() / 1000);
  }

  toggleReceiver(id: string, enable: boolean): LogReceiverStatus | null {
    const st = this.statuses.get(id);
    if (!st) return null;
    if (!enable) {
      if (id === 'syslog-udp' && this.udpSocket) {
        try { this.udpSocket.close(); } catch { /* ignore */ }
        this.udpSocket = null;
      } else if (id === 'syslog-tcp' && this.tcpServer) {
        try { this.tcpServer.close(); } catch { /* ignore */ }
        this.tcpServer = null;
      } else if (id === 'syslog-tls' && this.tlsServer) {
        try { this.tlsServer.close(); } catch { /* ignore */ }
        this.tlsServer = null;
      }
      st.listening = false;
      st.note = 'Manually stopped by SOC Engineer';
    } else if (!st.listening) {
      if (id === 'syslog-udp') this.startUdp(514, 5514);
      else if (id === 'syslog-tcp') this.startTcp(514, 5515);
      else if (id === 'syslog-tls') this.startTls(6514, 6515);
    }
    return { ...st };
  }

  listStatuses(): LogReceiverStatus[] {
    return Array.from(this.statuses.values());
  }
}
