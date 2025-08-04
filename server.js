import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import { promises as fs } from 'fs';
import { fileURLToPath } from 'url';

import DNSResolver from './lib/dns-resolver.js';
import DoHResolver from './lib/doh-resolver.js';
import DoTResolver from './lib/dot-resolver.js';
import DoQResolver from './lib/doq-resolver.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

const dnsResolver = new DNSResolver();
const dohResolver = new DoHResolver();
const dotResolver = new DoTResolver();
const doqResolver = new DoQResolver();

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/locales/:lang.json', async (req, res) => {
    try {
        const lang = req.params.lang;
        const filePath = path.join(__dirname, 'locales', `${lang}.json`);
        const data = await fs.readFile(filePath, 'utf8');
        res.json(JSON.parse(data));
    } catch (error) {
        res.status(404).json({ error: 'Language file not found' });
    }
});

app.post('/api/test', async (req, res) => {
    try {
        const { server, domain } = req.body;
        
        if (!server || !domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'Server and domain are required' 
            });
        }

        let result;
        
        switch (server.type) {
            case 'IPv4':
                result = await dnsResolver.resolveIPv4(domain, server);
                break;
            case 'IPv6':
                result = await dnsResolver.resolveIPv6(domain, server);
                break;
            case 'DoH':
                const dohType = req.body.queryType || 'A';
                result = await dohResolver.resolve(domain, server, dohType);
                break;
            case 'DoT':
                const dotType = req.body.queryType || 'A';
                result = await dotResolver.resolve(domain, server, dotType);
                break;
            case 'DoQ':
                const doqType = req.body.queryType || 'A';
                result = await doqResolver.resolve(domain, server, doqType);
                break;
            default:
                return res.status(400).json({
                    success: false,
                    error: `Unsupported DNS type: ${server.type}`
                });
        }

        res.json(result);
    } catch (error) {
        console.error('DNS test error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

app.get('/api/providers', async (req, res) => {
    try {
        const filePath = path.join(__dirname, 'public', 'data', 'dns-providers.json');
        const data = await fs.readFile(filePath, 'utf8');
        res.json(JSON.parse(data));
    } catch (error) {
        console.error('Failed to load providers:', error);
        res.status(500).json({ error: 'Failed to load DNS providers' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

wss.on('connection', (ws) => {
    console.log('WebSocket client connected');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            switch (data.type) {
                case 'startTest':
                    await handleTestRequest(ws, data.config);
                    break;
                case 'ping':
                    ws.send(JSON.stringify({ type: 'pong' }));
                    break;
                default:
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        error: 'Unknown message type' 
                    }));
            }
        } catch (error) {
            console.error('WebSocket message error:', error);
            ws.send(JSON.stringify({ 
                type: 'error', 
                error: error.message 
            }));
        }
    });
    
    ws.on('close', () => {
        console.log('WebSocket client disconnected');
    });
    
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

async function handleTestRequest(ws, config) {
    try {
        const { providers, domains, protocols, testCount, interval } = config;
        
        let totalTests = 0;
        let completedTests = 0;
        
        providers.forEach(provider => {
            provider.servers.forEach(server => {
                if (protocols.includes(server.type)) {
                    totalTests += domains.length * testCount;
                }
            });
        });

        ws.send(JSON.stringify({
            type: 'testStarted',
            totalTests: totalTests
        }));

        for (const provider of providers) {
            for (const server of provider.servers) {
                if (!protocols.includes(server.type)) continue;
                
                for (const domain of domains) {
                    for (let i = 0; i < testCount; i++) {
                        try {
                            let result;
                            
                            switch (server.type) {
                                case 'IPv4':
                                    result = await dnsResolver.resolveIPv4(domain, server);
                                    break;
                                case 'IPv6':
                                    result = await dnsResolver.resolveIPv6(domain, server);
                                    break;
                                case 'DoH':
                                    const dohQueryType = config.queryType || 'A';
                                    result = await dohResolver.resolve(domain, server, dohQueryType);
                                    break;
                                case 'DoT':
                                    const dotQueryType = config.queryType || 'A';
                                    result = await dotResolver.resolve(domain, server, dotQueryType);
                                    break;
                                case 'DoQ':
                                    const doqQueryType = config.queryType || 'A';
                                    result = await doqResolver.resolve(domain, server, doqQueryType);
                                    break;
                                default:
                                    result = {
                                        success: false,
                                        error: `Unsupported DNS type: ${server.type}`,
                                        server: server,
                                        domain: domain
                                    };
                            }

                            result.provider = provider.name;
                            result.iteration = i + 1;
                            result.timestamp = Date.now();

                            ws.send(JSON.stringify({
                                type: 'testResult',
                                result: result
                            }));

                            completedTests++;
                            const progress = (completedTests / totalTests) * 100;
                            
                            ws.send(JSON.stringify({
                                type: 'testProgress',
                                progress: progress,
                                completed: completedTests,
                                total: totalTests,
                                current: `${provider.name} - ${server.type}`
                            }));

                            if (interval > 0) {
                                await new Promise(resolve => setTimeout(resolve, interval * 1000));
                            }
                        } catch (error) {
                            console.error(`Test failed for ${provider.name}:`, error);
                            
                            ws.send(JSON.stringify({
                                type: 'testResult',
                                result: {
                                    success: false,
                                    error: error.message,
                                    provider: provider.name,
                                    server: server,
                                    domain: domain,
                                    iteration: i + 1,
                                    timestamp: Date.now()
                                }
                            }));
                        }
                    }
                }
            }
        }

        ws.send(JSON.stringify({
            type: 'testComplete',
            totalTests: totalTests,
            completedTests: completedTests
        }));
    } catch (error) {
        console.error('Test execution error:', error);
        ws.send(JSON.stringify({
            type: 'error',
            error: error.message
        }));
    }
}

app.use((err, req, res, next) => {
    console.error('Express error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

server.listen(PORT, () => {
    console.log(`YADNSB server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});