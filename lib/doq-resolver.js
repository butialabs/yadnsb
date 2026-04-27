import { performance } from 'perf_hooks';
import { webcrypto } from 'crypto';
import tls from 'tls';
import { QUICClient } from '@matrixai/quic';
import { buildQuery, parseResponse } from './dns-packet.js';

const clientCrypto = {
    ops: {
        async randomBytes(data) {
            webcrypto.getRandomValues(new Uint8Array(data));
        }
    }
};

const rootCAs = tls.rootCertificates.join('\n');

class DoQResolver {
    constructor() {
        this.timeout = 5000;
    }

    async resolve(domain, server, type = 'A') {
        const startTime = performance.now();
        const port = server.port || 853;

        console.log(`[DoQ] Request initiated: ${domain} (${type}) via ${server.name}`);

        const validTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR'];
        if (!validTypes.includes(type.toUpperCase())) {
            console.warn(`[DoQ] Invalid query type: ${type}, defaulting to A`);
            type = 'A';
        }

        let client;
        let timer;
        const timeoutPromise = new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(`DoQ timeout after ${this.timeout}ms`)), this.timeout);
        });

        try {
            const result = await Promise.race([
                this.runQuery(domain, server, type, port, (c) => { client = c; }),
                timeoutPromise
            ]);

            const responseTime = performance.now() - startTime;
            console.log(`[DoQ] Response successful: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);

            return {
                success: true,
                responseTime,
                result,
                server,
                domain,
                type
            };
        } catch (error) {
            const responseTime = performance.now() - startTime;
            const message = this.formatError(error, server);
            console.error(`[DoQ] Resolution failed: ${domain} (${type}) via ${server.name} - ${message}`);
            return {
                success: false,
                responseTime,
                error: message,
                server,
                domain,
                type
            };
        } finally {
            if (timer) clearTimeout(timer);
            if (client) {
                try { await client.destroy({ force: true }); } catch (_) {}
            }
        }
    }

    async runQuery(domain, server, type, port, registerClient) {
        const client = await QUICClient.createQUICClient({
            host: server.address,
            port,
            crypto: clientCrypto,
            config: {
                verifyPeer: true,
                ca: rootCAs,
                applicationProtos: ['doq']
            }
        });
        registerClient(client);

        const stream = client.connection.newStream('bidi');
        const query = buildQuery(domain, type, 0);
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(query.length, 0);
        const framed = Buffer.concat([lengthPrefix, query]);

        const writer = stream.writable.getWriter();
        try {
            await writer.write(framed);
            await writer.close();
        } finally {
            try { writer.releaseLock(); } catch (_) {}
        }

        const reader = stream.readable.getReader();
        const chunks = [];
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value && value.length) chunks.push(Buffer.from(value));
            }
        } finally {
            try { reader.releaseLock(); } catch (_) {}
        }

        const response = Buffer.concat(chunks);
        if (response.length < 2) throw new Error('DoQ response truncated');
        const expectedLength = response.readUInt16BE(0);
        const dnsMessage = response.subarray(2, 2 + expectedLength);
        if (dnsMessage.length < expectedLength) throw new Error('DoQ response shorter than declared length');

        return parseResponse(dnsMessage, type);
    }

    formatError(error, server) {
        const message = error?.message || String(error);
        if (/timeout/i.test(message)) return message;
        if (/ENOTFOUND/.test(message)) return `DoQ server not found: ${server.address}`;
        if (/ECONNREFUSED/.test(message)) return `Connection refused to ${server.address}`;
        if (/ENETUNREACH|EHOSTUNREACH/.test(message)) return `Network unreachable to ${server.address}`;
        if (/no application protocol|alpn/i.test(message)) {
            return `Server ${server.address}:${server.port || 853} did not negotiate ALPN "doq" — endpoint may not support DNS-over-QUIC`;
        }
        return `DoQ error: ${message}`;
    }

    setTimeout(timeout) {
        this.timeout = timeout;
    }
}

export default DoQResolver;
