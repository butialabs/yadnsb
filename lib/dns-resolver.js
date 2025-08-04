import { promises as dns } from 'dns';
import { performance } from 'perf_hooks';
import net from 'net';

class DNSResolver {
    constructor() {
        this.timeout = 5000;
        this.ipv6Available = null;
    }

    async checkIPv6Connectivity() {
        if (this.ipv6Available !== null) {
            return this.ipv6Available;
        }

        return new Promise((resolve) => {
            const ipv6Servers = [
                '2001:4860:4860::8888', // Google DNS
                '2606:4700:4700::1111', // Cloudflare DNS
                '2001:4860:4860::8844'  // Google DNS secundário
            ];
            
            let attempts = 0;
            let connected = false;
            
            const tryConnection = (serverIndex) => {
                if (serverIndex >= ipv6Servers.length) {
                    console.log('[DNS] IPv6 connectivity check failed - no servers reachable');
                    this.ipv6Available = false;
                    resolve(false);
                    return;
                }
                
                const socket = net.createConnection({
                    host: ipv6Servers[serverIndex],
                    port: 53,
                    family: 6,
                    timeout: 1500
                });

                socket.on('connect', () => {
                    socket.destroy();
                    if (!connected) {
                        connected = true;
                        console.log(`[DNS] IPv6 connectivity confirmed via ${ipv6Servers[serverIndex]}`);
                        this.ipv6Available = true;
                        resolve(true);
                    }
                });

                socket.on('error', (error) => {
                    console.log(`[DNS] IPv6 connection failed to ${ipv6Servers[serverIndex]}: ${error.code}`);
                    if (!connected) {
                        tryConnection(serverIndex + 1);
                    }
                });

                socket.on('timeout', () => {
                    socket.destroy();
                    console.log(`[DNS] IPv6 connection timeout to ${ipv6Servers[serverIndex]}`);
                    if (!connected) {
                        tryConnection(serverIndex + 1);
                    }
                });
            };
            
            tryConnection(0);
        });
    }

    async resolve(domain, server, type = 'A') {
        const startTime = performance.now();
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        console.log(`[DNS] Request initiated: ${domain} (${type}) via ${server.name}`);
        
        const isIPv6Server = server.address.includes(':') && !server.address.startsWith('[');
        if (isIPv6Server) {
            const ipv6Available = await this.checkIPv6Connectivity();
            if (!ipv6Available) {
                const endTime = performance.now();
                const responseTime = endTime - startTime;
                
                console.warn(`[DNS] IPv6 not available: ${domain} (${type}) via ${server.name}`);
                
                return {
                    success: false,
                    responseTime: responseTime,
                    error: 'IPv6 connectivity is not available on this system. Please check your network configuration or use IPv4 DNS servers.',
                    server: server,
                    domain: domain,
                    type: type,
                    ipv6Status: 'unavailable'
                };
            }
        }
        
        try {
            const resolver = new dns.Resolver();
            
            let serverAddress;
            if (isIPv6Server) {
                serverAddress = `[${server.address}]:${server.port || 53}`;
            } else {
                serverAddress = `${server.address}:${server.port || 53}`;
            }
            
            console.log(`[DNS] Setting server address: ${serverAddress} for ${domain} (${type})`);
            resolver.setServers([serverAddress]);
            
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error(`DNS query timeout after ${this.timeout}ms`)), this.timeout);
            });
            
            const queryPromise = (async () => {
                switch (type.toLowerCase()) {
                    case 'a':
                        return await resolver.resolve4(domain);
                    case 'aaaa':
                        return await resolver.resolve6(domain);
                    case 'mx':
                        return await resolver.resolveMx(domain);
                    case 'txt':
                        return await resolver.resolveTxt(domain);
                    case 'ns':
                        return await resolver.resolveNs(domain);
                    case 'cname':
                        return await resolver.resolveCname(domain);
                    default:
                        return await resolver.resolve4(domain);
                }
            })();
            
            const result = await Promise.race([queryPromise, timeoutPromise]);

            const endTime = performance.now();
            const responseTime = endTime - startTime;

            if (!Array.isArray(result)) {
                console.warn(`[DNS] Invalid response: DNS result is not an array for ${domain} (${type}) via ${server.name}`);
            } else if (result.length === 0) {
                console.warn(`[DNS] Empty result for ${domain} (${type}) via ${server.name}`);
            }

            const finalResult = {
                success: true,
                responseTime: responseTime,
                result: result,
                server: server,
                domain: domain,
                type: type
            };

            console.log(`[DNS] Response successful: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);
            return finalResult;
        } catch (error) {
            const endTime = performance.now();
            const responseTime = endTime - startTime;

            console.error(`[DNS] Resolution failed: ${domain} (${type}) via ${server.name} - ${error.message}`);

            const errorResult = {
                success: false,
                responseTime: responseTime,
                error: error.message,
                server: server,
                domain: domain,
                type: type
            };

            console.log(`[DNS] Response failed: ${domain} (${type}) via ${server.name} - ${Math.round(responseTime * 100) / 100}ms`);
            return errorResult;
        }
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