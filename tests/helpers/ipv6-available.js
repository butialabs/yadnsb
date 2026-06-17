import dgram from 'dgram';
import os from 'os';
import { buildQuery } from '../../lib/dns-packet.js';

const DEFAULT_IPV6_DNS = '2001:4860:4860::8888';
const DEFAULT_PORT = 53;
const DEFAULT_TIMEOUT = 3000;

export async function isIPv6UdpAvailable(host = DEFAULT_IPV6_DNS, port = DEFAULT_PORT, timeout = DEFAULT_TIMEOUT) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp6');
        let settled = false;
        let timer;

        const finish = (available) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { socket.close(); } catch (_) {}
            resolve(available);
        };

        timer = setTimeout(() => finish(false), timeout);

        socket.on('error', () => finish(false));
        socket.on('message', (msg) => {
            if (msg.length >= 2) finish(true);
        });

        try {
            const query = buildQuery('example.com', 'AAAA', 0x1234);
            socket.send(query, port, host, (err) => {
                if (err) finish(false);
            });
        } catch {
            finish(false);
        }
    });
}

export function hasIPv6Interface() {
    return Object.values(os.networkInterfaces())
        .flat()
        .some(iface => iface.family === 'IPv6' && !iface.internal);
}

export function ipv6SkipMessage() {
    return 'IPv6 external UDP connectivity not available on this host; skipping IPv6 resolver test.';
}
