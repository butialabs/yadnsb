import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import DoHResolver from '../lib/doh-resolver.js';

const resolver = new DoHResolver();
const TEST_DOMAIN = 'example.com';
const SERVERS = [
    { name: 'Cloudflare DoH', address: 'https://cloudflare-dns.com/dns-query', port: 443, method: 'GET', format: 'wireformat' },
    { name: 'Google DoH', address: 'https://dns.google/dns-query', port: 443, method: 'POST', format: 'wireformat' }
];

describe('DoH resolver integration', () => {
    for (const server of SERVERS) {
        it(`resolves A record for ${TEST_DOMAIN} via ${server.name}`, async () => {
            const result = await resolver.resolve(TEST_DOMAIN, server, 'A');
            assert.equal(result.success, true, `Expected success but got: ${result.error}`);
            assert.ok(Array.isArray(result.result), 'Expected result to be an array');
            assert.ok(result.result.length > 0, 'Expected at least one answer');
            assert.ok(result.responseTime > 0, 'Expected positive response time');
            for (const ip of result.result) {
                assert.match(ip, /^(\d{1,3}\.){3}\d{1,3}$/, `Expected IPv4 address, got ${ip}`);
            }
        });

        it(`resolves AAAA record for ${TEST_DOMAIN} via ${server.name}`, async () => {
            const result = await resolver.resolve(TEST_DOMAIN, server, 'AAAA');
            assert.equal(result.success, true, `Expected success but got: ${result.error}`);
            assert.ok(Array.isArray(result.result), 'Expected result to be an array');
            assert.ok(result.result.length > 0, 'Expected at least one answer');
            for (const ip of result.result) {
                assert.ok(/^[0-9a-f:]+$/i.test(ip), `Expected IPv6 address, got ${ip}`);
            }
        });
    }
});
