import dgram from 'dgram';
import { performance } from 'perf_hooks';
import { buildQuery, parseResponse } from './dns-packet.js';

class DNSResolver {
    constructor() {
        this.timeout = 5000;
    }

    async resolve(domain, server, type = 'A') {
        const startTime = performance.now();
        const isIPv6Server = server.address.includes(':');
        const socketType = isIPv6Server ? 'udp6' : 'udp4';
        const port = server.port || 53;

        console.log(`[DNS] Request initiated: ${domain} (${type}) via ${server.name}`);

        return new Promise((resolve) => {
            const socket = dgram.createSocket(socketType);
            let settled = false;
            let timeoutHandle;

            const finish = (result) => {
                if (settled) return;
                settled = true;
                if (timeoutHandle) clearTimeout(timeoutHandle);
                try { socket.close(); } catch (_) {}
                resolve(result);
            };

            const fail = (errorMessage) => {
                const responseTime = performance.now() - startTime;
                console.error(`[DNS] Resolution failed: ${domain} (${type}) via ${server.name} - ${errorMessage}`);
                finish({
                    success: false,
                    responseTime,
                    error: errorMessage,
                    server,
                    domain,
                    type,
                    ...(isIPv6Server ? { ipv6Status: 'failed' } : {})
                });
            };

            timeoutHandle = setTimeout(() => {
                fail(`DNS query timeout after ${this.timeout}ms`);
            }, this.timeout);

            let query;
            try {
                query = buildQuery(domain, type);
            } catch (error) {
                fail(`Failed to build DNS query: ${error.message}`);
                return;
            }

            const expectedId = query.readUInt16BE(0);

            socket.on('message', (msg) => {
                try {
                    if (msg.length >= 2 && msg.readUInt16BE(0) !== expectedId) return;
                    const answers = parseResponse(msg, type);
                    const responseTime = performance.now() - startTime;

                    if (answers.length === 0) {
                        console.warn(`[DNS] Empty result for ${domain} (${type}) via ${server.name}`);
                    }

                    console.log(`[DNS] Response successful: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);
                    finish({
                        success: true,
                        responseTime,
                        result: answers,
                        server,
                        domain,
                        type
                    });
                } catch (error) {
                    fail(`Failed to parse DNS response: ${error.message}`);
                }
            });

            socket.on('error', (error) => {
                let message = error.message;
                if (error.code === 'ENETUNREACH' || error.code === 'EHOSTUNREACH') {
                    message = isIPv6Server
                        ? `IPv6 network unreachable: ${error.code}. Verify IPv6 connectivity to ${server.address}.`
                        : `Network unreachable: ${error.code}.`;
                } else if (error.code === 'EADDRNOTAVAIL') {
                    message = `Address not available: ${error.code}. ${isIPv6Server ? 'IPv6 may not be configured on this host.' : ''}`;
                }
                fail(message);
            });

            socket.send(query, port, server.address, (err) => {
                if (err) {
                    let message = err.message;
                    if (err.code === 'ENETUNREACH' || err.code === 'EHOSTUNREACH') {
                        message = isIPv6Server
                            ? `IPv6 network unreachable. Verify IPv6 connectivity to ${server.address}.`
                            : `Network unreachable to ${server.address}.`;
                    }
                    fail(message);
                }
            });
        });
    }

    async resolveIPv4(domain, server) {
        return this.resolve(domain, server, 'A');
    }

    async resolveIPv6(domain, server) {
        return this.resolve(domain, server, 'AAAA');
    }

    setTimeout(timeout) {
        this.timeout = timeout;
    }
}

export default DNSResolver;
