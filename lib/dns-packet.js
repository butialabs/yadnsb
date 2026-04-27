const TYPES = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    PTR: 12,
    MX: 15,
    TXT: 16,
    AAAA: 28
};

const TYPE_NAMES = Object.fromEntries(
    Object.entries(TYPES).map(([k, v]) => [v, k])
);

export function getDNSType(type) {
    return TYPES[type.toUpperCase()] || 1;
}

export function buildQuery(domain, type, id = null) {
    const queryId = id ?? Math.floor(Math.random() * 65536);
    const labels = domain.split('.').filter(Boolean);
    const nameLength = labels.reduce((sum, l) => sum + 1 + l.length, 0) + 1;
    const buf = Buffer.alloc(12 + nameLength + 4);
    let offset = 0;

    buf.writeUInt16BE(queryId, offset); offset += 2;
    buf.writeUInt16BE(0x0100, offset); offset += 2;
    buf.writeUInt16BE(1, offset); offset += 2;
    buf.writeUInt16BE(0, offset); offset += 2;
    buf.writeUInt16BE(0, offset); offset += 2;
    buf.writeUInt16BE(0, offset); offset += 2;

    for (const label of labels) {
        if (label.length > 63) throw new Error(`DNS label too long: ${label}`);
        buf.writeUInt8(label.length, offset++);
        buf.write(label, offset, 'ascii');
        offset += label.length;
    }
    buf.writeUInt8(0, offset++);

    buf.writeUInt16BE(getDNSType(type), offset); offset += 2;
    buf.writeUInt16BE(1, offset); offset += 2;

    return buf;
}

function readName(buffer, offset) {
    const labels = [];
    let jumped = false;
    let originalOffset = offset;
    let safety = 0;

    while (true) {
        if (safety++ > 128) throw new Error('Name parsing loop');
        const len = buffer[offset];
        if (len === 0) {
            offset += 1;
            break;
        }
        if ((len & 0xC0) === 0xC0) {
            const pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
            if (!jumped) originalOffset = offset + 2;
            offset = pointer;
            jumped = true;
            continue;
        }
        offset += 1;
        labels.push(buffer.toString('ascii', offset, offset + len));
        offset += len;
    }

    return {
        name: labels.join('.'),
        offset: jumped ? originalOffset : offset
    };
}

function normalizeIPv6(parts) {
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === 0) {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else {
            curStart = -1; curLen = 0;
        }
    }

    const hex = parts.map(p => p.toString(16));
    if (bestLen < 2) return hex.join(':');

    const before = hex.slice(0, bestStart).join(':');
    const after = hex.slice(bestStart + bestLen).join(':');
    return `${before}::${after}`;
}

export function parseResponse(buffer, expectedType) {
    if (buffer.length < 12) throw new Error('Response too short');

    const flags = buffer.readUInt16BE(2);
    const rcode = flags & 0x0F;
    if (rcode !== 0) {
        const codes = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
        throw new Error(`DNS error: ${codes[rcode] || `RCODE ${rcode}`}`);
    }

    const qdcount = buffer.readUInt16BE(4);
    const ancount = buffer.readUInt16BE(6);

    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
        offset = readName(buffer, offset).offset;
        offset += 4;
    }

    const expectedTypeNum = getDNSType(expectedType);
    const answers = [];

    for (let i = 0; i < ancount; i++) {
        offset = readName(buffer, offset).offset;
        const rrType = buffer.readUInt16BE(offset); offset += 2;
        offset += 2;
        offset += 4;
        const rdlength = buffer.readUInt16BE(offset); offset += 2;
        const rdataStart = offset;

        if (rrType === expectedTypeNum) {
            if (rrType === TYPES.A && rdlength === 4) {
                answers.push(`${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`);
            } else if (rrType === TYPES.AAAA && rdlength === 16) {
                const parts = [];
                for (let j = 0; j < 8; j++) parts.push(buffer.readUInt16BE(offset + j * 2));
                answers.push(normalizeIPv6(parts));
            } else if (rrType === TYPES.CNAME || rrType === TYPES.NS || rrType === TYPES.PTR) {
                answers.push(readName(buffer, offset).name);
            } else if (rrType === TYPES.MX) {
                const preference = buffer.readUInt16BE(offset);
                const exchange = readName(buffer, offset + 2).name;
                answers.push(`${preference} ${exchange}`);
            } else if (rrType === TYPES.TXT) {
                const strings = [];
                let p = offset;
                while (p < offset + rdlength) {
                    const len = buffer[p];
                    strings.push(buffer.toString('utf8', p + 1, p + 1 + len));
                    p += 1 + len;
                }
                answers.push(strings.join(''));
            } else if (rrType === TYPES.SOA) {
                const mname = readName(buffer, offset);
                const rname = readName(buffer, mname.offset);
                answers.push(`${mname.name} ${rname.name}`);
            }
        }

        offset = rdataStart + rdlength;
    }

    return answers;
}
