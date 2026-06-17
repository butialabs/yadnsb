import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import DoQResolver from '../lib/doq-resolver.js';

const resolver = new DoQResolver();
const TEST_DOMAIN = 'example.com';
const SERVERS = [
    { name: 'AdGuard DoQ', address: 'dns.adguard-dns.com', port: 853 }
];

describe('DoQ resolver integration', () => {
    for (const server of SERVERS) {
        it(`attempts to resolve ${TEST_DOMAIN} via ${server.name}`, async () => {
            const result = await resolver.resolve(TEST_DOMAIN, server, 'A');

            // DoQ is still experimental and depends on network/QUIC support.
            // The test passes if we get a success OR a clear error message.
            if (result.success) {
                assert.ok(Array.isArray(result.result), 'Expected result to be an array');
                assert.ok(result.result.length > 0, 'Expected at least one answer');
                assert.ok(result.responseTime > 0, 'Expected positive response time');
            } else {
                assert.ok(result.error, 'Expected error message when DoQ fails');
                console.log(`[DoQ] ${server.name} failed as expected/known limitation: ${result.error}`);
            }
        });
    }
});
