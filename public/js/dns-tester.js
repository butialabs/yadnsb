class DNSTester {
    constructor() {
        this.isRunning = false;
        this.currentTest = null;
        this.results = [];
        this.websocket = null;
        this.testQueue = [];
        this.completedTests = 0;
        this.totalTests = 0;
    }

    async startTest(config) {
        if (this.isRunning) {
            console.warn('Test already running');
            return;
        }

        this.isRunning = true;
        this.results = [];
        this.testQueue = this.buildTestQueue(config);
        this.totalTests = this.testQueue.length;
        this.completedTests = 0;

        this.updateProgress(0, 'Starting DNS benchmark...');

        try {
            await this.connectWebSocket();
            await this.executeTests(config);
        } catch (error) {
            console.error('Test execution failed:', error);
            this.handleTestError(error);
        } finally {
            this.isRunning = false;
            this.disconnectWebSocket();
        }
    }

    buildTestQueue(config) {
        const queue = [];
        const domains = this.getTestDomains(config);

        config.selectedProviders.forEach(provider => {
            provider.servers.forEach(server => {
                if (config.selectedProtocols.includes(server.type)) {
                    domains.forEach(domain => {
                        const queryTypes = this.getQueryTypesForServer(server, config.queryType);
                        
                        queryTypes.forEach(queryType => {
                            for (let i = 0; i < config.testCount; i++) {
                                queue.push({
                                    provider: provider.name,
                                    server: { ...server, name: provider.name },
                                    domain: domain,
                                    iteration: i + 1,
                                    queryType: queryType
                                });
                            }
                        });
                    });
                }
            });
        });

        return this.shuffleArray(queue);
    }

    getQueryTypesForServer(server, configQueryType) {
        if (server.type === 'IPv4') return ['A'];
        if (server.type === 'IPv6') return ['AAAA'];
        
        if (['DoH', 'DoT', 'DoQ'].includes(server.type)) {
            switch (configQueryType) {
                case 'A': return ['A'];
                case 'AAAA': return ['AAAA'];
                case 'BOTH': return ['A', 'AAAA'];
                default: return ['A'];
            }
        }
        
        return ['A'];
    }

    getTestDomains(config) {
        let domains = [];

        if (config.usePresetDomains && config.selectedPresetDomains.length > 0) {
            domains = domains.concat(config.selectedPresetDomains);
        }

        if (config.customDomains && config.customDomains.trim()) {
            const customDomains = config.customDomains
                .split('\n')
                .map(d => d.trim())
                .filter(d => d && this.isValidDomain(d));
            domains = domains.concat(customDomains);
        }

        return [...new Set(domains)];
    }

    isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain) && domain.length <= 253;
    }

    shuffleArray(array) {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }

    async connectWebSocket() {
        return new Promise((resolve, reject) => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;

            this.websocket = new WebSocket(wsUrl);

            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                resolve();
            };

            this.websocket.onmessage = (event) => {
                this.handleWebSocketMessage(JSON.parse(event.data));
            };

            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
                reject(error);
            };

            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
            };
        });
    }

    disconnectWebSocket() {
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
    }

    async executeTests(config) {
        for (let i = 0; i < this.testQueue.length && this.isRunning; i++) {
            const test = this.testQueue[i];

            this.updateProgress(
                (i / this.totalTests) * 100,
                `Testing ${test.provider} - ${test.server.type} (${i + 1}/${this.totalTests})`
            );

            try {
                const result = await this.performSingleTest(test);
                this.results.push(result);
                this.completedTests++;

                window.dispatchEvent(new CustomEvent('testProgress', {
                    detail: {
                        percentage: (this.completedTests / this.totalTests) * 100,
                        status: `Testing ${test.provider} - ${test.server.type} (${this.completedTests}/${this.totalTests})`,
                        results: [...this.results]
                    }
                }));

                if (config.testInterval > 0) {
                    await this.sleep(config.testInterval * 1000);
                }
            } catch (error) {
                console.error(`Test failed for ${test.provider}:`, error);
                const failedResult = {
                    provider: test.provider,
                    server: test.server,
                    domain: test.domain,
                    iteration: test.iteration,
                    responseTime: null,
                    success: false,
                    error: error.message,
                    timestamp: Date.now()
                };
                this.results.push(failedResult);
                this.completedTests++;

                window.dispatchEvent(new CustomEvent('testProgress', {
                    detail: {
                        percentage: (this.completedTests / this.totalTests) * 100,
                        status: `Testing ${test.provider} - ${test.server.type} (${this.completedTests}/${this.totalTests})`,
                        results: [...this.results]
                    }
                }));
            }
        }

        this.updateProgress(100, 'Test completed');

        window.dispatchEvent(new CustomEvent('testProgress', {
            detail: {
                percentage: 100,
                status: 'Test completed',
                results: [...this.results],
                completed: true
            }
        }));
    }

    async performSingleTest(test) {
        const startTime = performance.now();

        try {
            const requestBody = {
                server: test.server,
                domain: test.domain
            };
            
            if (['DoH', 'DoT', 'DoQ'].includes(test.server.type) && test.queryType) {
                requestBody.queryType = test.queryType;
            }

            const response = await fetch('/api/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            const endTime = performance.now();
            const responseTime = endTime - startTime;

            return {
                provider: test.provider,
                server: test.server,
                domain: test.domain,
                iteration: test.iteration,
                responseTime: result.success ? result.responseTime : null,
                totalTime: responseTime,
                success: result.success,
                error: result.error || null,
                timestamp: Date.now()
            };
        } catch (error) {
            const endTime = performance.now();
            const responseTime = endTime - startTime;

            return {
                provider: test.provider,
                server: test.server,
                domain: test.domain,
                iteration: test.iteration,
                responseTime: null,
                totalTime: responseTime,
                success: false,
                error: error.message,
                timestamp: Date.now()
            };
        }
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'testProgress':
                this.updateProgress(message.progress, message.status);
                break;
            case 'testResult':
                this.results.push(message.result);
                break;
            case 'testComplete':
                this.isRunning = false;
                this.updateProgress(100, 'Test completed');
                break;
            case 'error':
                this.handleTestError(new Error(message.error));
                break;
        }
    }

    updateProgress(percentage, status) {
        const progressBar = document.getElementById('overallProgress');
        const statusElement = document.getElementById('currentTest');

        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
        }

        if (statusElement) {
            statusElement.textContent = status;
        }

        window.dispatchEvent(new CustomEvent('testProgress', {
            detail: {
                percentage,
                status,
                results: [...this.results]
            }
        }));
    }

    handleTestError(error) {
        console.error('Test error:', error);
        this.isRunning = false;
        this.updateProgress(0, `Error: ${error.message}`);

        window.dispatchEvent(new CustomEvent('testError', {
            detail: { error: error.message }
        }));
    }

    stopTest() {
        this.isRunning = false;
        this.updateProgress(0, 'Test stopped by user');
        this.disconnectWebSocket();
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getResults() {
        return this.results;
    }

    clearResults() {
        this.results = [];
        this.completedTests = 0;
        this.totalTests = 0;
        this.updateProgress(0, 'Ready to start testing');
    }
}

window.dnsTester = new DNSTester();