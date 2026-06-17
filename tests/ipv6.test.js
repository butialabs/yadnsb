import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import DNSResolver from '../lib/dns-resolver.js';
import { isIPv6UdpAvailable, ipv6SkipMessage } from './helpers/ipv6-available.js';

const resolver = new DNSResolver();
const TEST_DOMAIN = 'example.com';
const SERVERS = [
    { name: 'Cloudflare IPv6', address: '2606:4700:4700::1111', port: 53 },
    { name: 'Google IPv6', address: '2001:4860:4860::8888', port: 53 }
];

let ipv6Available = null;

async function checkIPv6() {
    if (ipv6Available === null) {
        ipv6Available = await isIPv6UdpAvailable();
    }
    return ipv6Available;
}

describe('IPv6 resolver integration', () => {
    for (const server of SERVERS) {
        it(`resolves ${TEST_DOMAIN} via ${server.name}`, async () => {
            if (!(await checkIPv6())) {
                return it.skip(ipv6SkipMessage());
            }

            const result = await resolver.resolveIPv6(TEST_DOMAIN, server);
            assert.equal(result.success, true, `Expected success but got: ${result.error}`);
            assert.ok(Array.isArray(result.result), 'Expected result to be an array');
            assert.ok(result.result.length > 0, 'Expected at least one answer');
            assert.ok(result.responseTime > 0, 'Expected positive response time');
            for (const ip of result.result) {
                assert.ok(/^[0-9a-f:]+$/i.test(ip), `Expected IPv6 address, got ${ip}`);
            }
        });
    }
});
