import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import DoTResolver from '../lib/dot-resolver.js';

const resolver = new DoTResolver();
const TEST_DOMAIN = 'example.com';
const SERVERS = [
    { name: 'Google DoT', address: 'dns.google', port: 853 },
    { name: 'AdGuard DoT', address: 'dns.adguard-dns.com', port: 853 }
];

describe('DoT resolver integration', () => {
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
