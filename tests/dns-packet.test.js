import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildQuery, parseResponse, getDNSType } from '../lib/dns-packet.js';

function writeName(name) {
    const parts = [];
    for (const label of name.split('.')) {
        const labelBuf = Buffer.alloc(1 + label.length);
        labelBuf.writeUInt8(label.length, 0);
        labelBuf.write(label, 1, 'ascii');
        parts.push(labelBuf);
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
}

function buildResponse(query, answers, rcode = 0) {
    const nameBuf = writeName(query);
    const question = Buffer.concat([
        nameBuf,
        Buffer.from([0x00, getDNSType('AAAA'), 0x00, 0x01])
    ]);

    const answerBuffers = [];
    for (const answer of answers) {
        const typeNum = getDNSType(answer.type);
        const rdata = answer.rdata;
        const ttl = Buffer.alloc(4);
        ttl.writeUInt32BE(300, 0);
        answerBuffers.push(Buffer.concat([
            Buffer.from([0xC0, 0x0C]), // pointer to query name
            Buffer.from([0x00, typeNum]), // type
            Buffer.from([0x00, 0x01]), // class IN
            ttl,
            Buffer.from([(rdata.length >> 8) & 0xFF, rdata.length & 0xFF]), // rdlength
            rdata
        ]));
    }

    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1234, 0);
    header.writeUInt16BE(0x8180 | (rcode & 0x0F), 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answers.length, 6);

    return Buffer.concat([header, question, ...answerBuffers]);
}

describe('dns-packet', () => {
    describe('getDNSType', () => {
        it('returns correct numeric types', () => {
            assert.equal(getDNSType('A'), 1);
            assert.equal(getDNSType('AAAA'), 28);
            assert.equal(getDNSType('MX'), 15);
            assert.equal(getDNSType('TXT'), 16);
            assert.equal(getDNSType('CNAME'), 5);
            assert.equal(getDNSType('NS'), 2);
            assert.equal(getDNSType('PTR'), 12);
            assert.equal(getDNSType('SOA'), 6);
        });

        it('defaults to A for unknown types', () => {
            assert.equal(getDNSType('UNKNOWN'), 1);
        });
    });

    describe('buildQuery', () => {
        it('creates a valid DNS query buffer', () => {
            const query = buildQuery('example.com', 'A', 0x1234);
            assert.ok(query.length > 12);
            assert.equal(query.readUInt16BE(0), 0x1234);
            assert.equal(query.readUInt16BE(2), 0x0100);
            assert.equal(query.readUInt16BE(4), 1);
        });

        it('uses random id when id is null', () => {
            const query = buildQuery('example.com', 'A');
            assert.ok(query.readUInt16BE(0) >= 0);
        });

        it('throws on labels longer than 63 bytes', () => {
            const longLabel = 'a'.repeat(64);
            assert.throws(() => buildQuery(`${longLabel}.com`, 'A'), /label too long/);
        });
    });

    describe('parseResponse', () => {
        it('parses A record answer', () => {
            const response = buildResponse('example.com', [
                { type: 'A', rdata: Buffer.from([93, 184, 216, 34]) }
            ]);
            const answers = parseResponse(response, 'A');
            assert.deepEqual(answers, ['93.184.216.34']);
        });

        it('parses AAAA record answer', () => {
            const rdata = Buffer.from([
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
            ]);
            const response = buildResponse('example.com', [
                { type: 'AAAA', rdata }
            ]);
            const answers = parseResponse(response, 'AAAA');
            assert.deepEqual(answers, ['2001:db8::1']);
        });

        it('parses CNAME record answer', () => {
            const rdata = writeName('cdn.example.net');
            const response = buildResponse('example.com', [
                { type: 'CNAME', rdata }
            ]);
            const answers = parseResponse(response, 'CNAME');
            assert.deepEqual(answers, ['cdn.example.net']);
        });

        it('parses MX record answer', () => {
            const exchange = writeName('mail.example.com');
            const rdata = Buffer.concat([
                Buffer.from([0x00, 0x0A]), // preference
                exchange
            ]);
            const response = buildResponse('example.com', [
                { type: 'MX', rdata }
            ]);
            const answers = parseResponse(response, 'MX');
            assert.deepEqual(answers, ['10 mail.example.com']);
        });

        it('parses TXT record answer', () => {
            const text = 'v=spf1 include:_spf.example.com ~all';
            const rdata = Buffer.concat([
                Buffer.from([text.length]),
                Buffer.from(text, 'utf8')
            ]);
            const response = buildResponse('example.com', [
                { type: 'TXT', rdata }
            ]);
            const answers = parseResponse(response, 'TXT');
            assert.deepEqual(answers, [text]);
        });

        it('throws on short buffer', () => {
            assert.throws(() => parseResponse(Buffer.from([0, 0]), 'A'), /too short/);
        });

        it('throws on non-zero RCODE', () => {
            const response = buildResponse('example.com', [], 3); // NXDOMAIN
            assert.throws(() => parseResponse(response, 'A'), /NXDOMAIN/);
        });
    });
});
