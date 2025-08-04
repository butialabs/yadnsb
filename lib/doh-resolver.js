import pkg from 'dohjs';
const { DohResolver, makeQuery, sendDohMsg } = pkg;
import { performance } from 'perf_hooks';

class DoHResolver {
    constructor() {
        this.timeout = 5000;
    }

    getProviderConfig(server) {
        if (server.method && server.format) {
            return {
                method: server.method,
                format: server.format
            };
        }
        return { method: 'GET', format: 'wireformat' };
    }

    async resolve(domain, server, type = 'A') {
        const startTime = performance.now();
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        console.log(`[DoH] Request initiated: ${domain} (${type}) via ${server.name}`);
        
        const validTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR'];
        if (!validTypes.includes(type.toUpperCase())) {
            console.warn(`[DoH] Invalid query type: ${type}, defaulting to A`);
            type = 'A';
        }
        
        const config = this.getProviderConfig(server);
        
        try {
            return await this.resolveWithDohjs(domain, server, type, requestId, startTime, config);
        } catch (error) {
            console.warn(`[DoH] Primary method failed, trying fallback: ${domain} (${type}) via ${server.name} - ${error.message}`);
            
            try {
                const fallbackConfig = {
                    method: config.method === 'POST' ? 'GET' : 'POST',
                    format: 'wireformat'
                };
                return await this.resolveWithDohjs(domain, server, type, requestId, startTime, fallbackConfig);
            } catch (fallbackError) {
                return this.handleError(fallbackError, domain, server, type, requestId, startTime);
            }
        }
    }

    async resolveWithDohjs(domain, server, type, requestId, startTime, config) {
        let url = new URL(server.address);
        
        if (!url.pathname.includes('dns-query')) {
            url.pathname = url.pathname.endsWith('/') ? url.pathname + 'dns-query' : url.pathname + '/dns-query';
        }

        const resolver = new DohResolver(url.toString());
        
        const headers = {
            'Accept': 'application/dns-message',
            'User-Agent': 'YADNSB/1.0'
        };

        if (config.method === 'POST') {
            headers['Content-Type'] = 'application/dns-message';
        }

        try {
            console.log(`[DoH-${config.method}] Sending request: ${domain} (${type}) via ${server.name}`);
            
            const response = await resolver.query(domain, type, config.method, headers, this.timeout);
            
            const endTime = performance.now();
            const responseTime = endTime - startTime;

            console.log(`[DoH-${config.method}] HTTP request successful for ${domain} (${type}) via ${server.name}`);

            const result = this.extractAnswersFromDohjs(response, type);

            const finalResult = {
                success: true,
                responseTime: responseTime,
                result: result,
                server: server,
                domain: domain,
                type: type,
                method: config.method,
                rawResponse: response
            };

            console.log(`[DoH-${config.method}] Response successful: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);
            return finalResult;
        } catch (error) {
            console.error(`[DoH-${config.method}] Request failed: ${domain} (${type}) via ${server.name} - ${error.message}`);
            throw error;
        }
    }

    extractAnswersFromDohjs(response, type) {
        if (!response.answers || response.answers.length === 0) {
            console.warn(`[DoH] Response missing answers for ${type} query`);
            return [];
        }

        const dnsType = this.getDNSType(type);
        
        return response.answers
            .filter(answer => {
                if (!answer.hasOwnProperty('type') || !answer.hasOwnProperty('data')) {
                    console.warn(`[DoH] Invalid answer record structure`);
                    return false;
                }
                
                return answer.type === type || answer.type === type.toUpperCase();
            })
            .map(answer => {
                if (answer.type === 'A') {
                    // IPv4 address
                    return answer.data;
                } else if (answer.type === 'AAAA') {
                    // IPv6 address
                    if (typeof answer.data === 'string') {
                        return this.normalizeIPv6(answer.data);
                    }
                    return answer.data;
                } else if (answer.type === 'TXT') {
                    return Array.isArray(answer.data) ? answer.data.join('') : answer.data.toString();
                } else if (answer.type === 'MX') {
                    if (typeof answer.data === 'object' && answer.data.preference !== undefined) {
                        return `${answer.data.preference} ${answer.data.exchange}`;
                    }
                    return answer.data.toString();
                } else if (answer.type === 'CNAME' || answer.type === 'NS' || answer.type === 'PTR') {
                    return answer.data;
                } else {
                    return answer.data.toString();
                }
            });
    }

    handleError(error, domain, server, type, requestId, startTime) {
        const endTime = performance.now();
        const responseTime = endTime - startTime;

        let errorMessage = error.message;
        
        if (error.name === 'AbortError' || error.message.includes('timed out')) {
            errorMessage = `Request timeout after ${this.timeout}ms`;
        } else if (error.code === 'ENOTFOUND') {
            errorMessage = `DNS server not found: ${server.address}`;
        } else if (error.code === 'ECONNREFUSED') {
            errorMessage = `Connection refused to ${server.address}`;
        } else if (error.message.includes('Unexpected token')) {
            errorMessage = `Invalid response from DoH server`;
        }

        const errorResult = {
            success: false,
            responseTime: responseTime,
            error: errorMessage,
            server: server,
            domain: domain,
            type: type
        };

        console.log(`[DoH] Response failed: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);
        return errorResult;
    }

    getDNSType(type) {
        const types = {
            'A': 1,
            'AAAA': 28,
            'MX': 15,
            'TXT': 16,
            'NS': 2,
            'CNAME': 5,
            'SOA': 6,
            'PTR': 12
        };
        return types[type.toUpperCase()] || 1;
    }

    normalizeIPv6(ipv6) {
        try {
            let normalized = ipv6.trim().toLowerCase();
            
            if (/^[0-9a-f:]+$/.test(normalized)) {
                return normalized;
            }
            
            return ipv6;
        } catch (error) {
            console.warn(`[DoH] Failed to normalize IPv6 address: ${ipv6}`);
            return ipv6;
        }
    }

    setTimeout(timeout) {
        this.timeout = timeout;
    }
}

export default DoHResolver;