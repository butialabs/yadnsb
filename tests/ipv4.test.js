import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import DNSResolver from '../lib/dns-resolver.js';

const resolver = new DNSResolver();
const TEST_DOMAIN = 'example.com';
const SERVERS = [
    { name: 'Cloudflare IPv4', address: '1.1.1.1', port: 53 },
    { name: 'Google IPv4', address: '8.8.8.8', port: 53 }
];

describe('IPv4 resolver integration', () => {
    for (const server of SERVERS) {
        it(`resolves ${TEST_DOMAIN} via ${server.name}`, async () => {
            const result = await resolver.resolveIPv4(TEST_DOMAIN, server);
            assert.equal(result.success, true, `Expected success but got: ${result.error}`);
            assert.ok(Array.isArray(result.result), 'Expected result to be an array');
            assert.ok(result.result.length > 0, 'Expected at least one answer');
            assert.ok(result.responseTime > 0, 'Expected positive response time');
            for (const ip of result.result) {
                assert.match(ip, /^(\d{1,3}\.){3}\d{1,3}$/, `Expected IPv4 address, got ${ip}`);
            }
        });
    }

    it('handles invalid server gracefully', async () => {
        const result = await resolver.resolveIPv4(TEST_DOMAIN, { name: 'Invalid', address: '256.256.256.256', port: 53 });
        assert.equal(result.success, false);
        assert.ok(result.error);
    });
});
