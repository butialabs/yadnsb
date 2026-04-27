class YADNSBApp {
    constructor() {
        this.providers = [];
        this.selectedProviders = [];
        this.isTestRunning = false;
        this.expandedGroups = new Set(); // Track which groups are expanded
        this.init();
    }

    async init() {
        await this.loadProviders();
        this.setupEventListeners();
        this.renderProviders();
        this.renderPresetDomains();
        this.updateUI();
        this.loadSavedLanguage();

        resultsManager.displayResults();
    }

    async loadProviders() {
        try {
            const response = await fetch('/data/dns-providers.json');
            const data = await response.json();
            this.providers = this.normalizeProviders(data.providers);
            this.testDomains = data.testDomains;

            if (window.customProvidersManager) {
                const customProviders = window.customProvidersManager.getCustomProviders();
                this.providers = [...this.providers, ...customProviders];
            }
        } catch (error) {
            console.error('Failed to load DNS providers:', error);
            this.providers = [];
            this.testDomains = [];
        }
    }

    normalizeProviders(providers) {
        const normalized = [];
        
        providers.forEach(provider => {
            if (provider.groups) {
                const mainProvider = {
                    name: provider.name,
                    isMainProvider: true,
                    groups: provider.groups.map(group => ({
                        name: `${provider.name} (${group.name})`,
                        servers: group.servers,
                        parentProvider: provider.name,
                        groupName: group.name
                    })),
                    servers: []
                };
                normalized.push(mainProvider);
                
                provider.groups.forEach(group => {
                    normalized.push({
                        name: `${provider.name} (${group.name})`,
                        servers: group.servers,
                        parentProvider: provider.name,
                        groupName: group.name,
                        isSubGroup: true
                    });
                });
            } else {
                normalized.push(provider);
            }
        });
        
        return normalized;
    }

    refreshProviders() {
        this.loadProviders().then(() => {
            this.renderProviders();
        });
    }

    setupEventListeners() {
        document.getElementById('startTest').addEventListener('click', () => this.startTest());
        document.getElementById('stopTest').addEventListener('click', () => this.stopTest());

        document.getElementById('selectAllProviders').addEventListener('click', () => this.selectAllProviders());
        document.getElementById('deselectAllProviders').addEventListener('click', () => this.deselectAllProviders());
        document.getElementById('expandAllGroups').addEventListener('click', () => this.expandAllGroups());
        document.getElementById('collapseAllGroups').addEventListener('click', () => this.collapseAllGroups());
        document.getElementById('addCustomProvider').addEventListener('click', () => this.addCustomProvider());

        document.getElementById('exportCSV').addEventListener('click', () => this.exportCSV());
        document.getElementById('exportJSON').addEventListener('click', () => this.exportJSON());
        document.getElementById('clearResults').addEventListener('click', () => this.clearResults());

        document.getElementById('sortBy').addEventListener('change', (e) => {
            resultsManager.setSortBy(e.target.value);
        });

        document.querySelectorAll('.protocol-filter').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.filterProviders());
        });

        document.querySelectorAll('[data-lang]').forEach(langLink => {
            langLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.changeLanguage(e.target.closest('[data-lang]').dataset.lang);
            });
        });

        document.getElementById('usePresetDomains').addEventListener('change', (e) => {
            const presetSelect = document.getElementById('presetDomains');
            presetSelect.disabled = !e.target.checked;
            if (e.target.checked) {
                presetSelect.querySelectorAll('option').forEach(option => option.selected = true);
            }
        });

        window.addEventListener('testProgress', (e) => {
            resultsManager.setResults(e.detail.results);
        });

        window.addEventListener('testError', (e) => {
            this.handleTestError(e.detail.error);
        });
    }

    renderProviders() {
        const container = document.getElementById('providersList');
        if (!container) return;

        const selectedProtocols = this.getSelectedProtocols();

        const filteredProviders = this.providers.filter(provider => {
            if (provider.isMainProvider) {
                return provider.groups.some(group =>
                    group.servers.some(server => selectedProtocols.includes(server.type))
                );
            } else if (provider.isSubGroup) {
                return provider.servers.some(server => selectedProtocols.includes(server.type));
            } else {
                return provider.servers.some(server => selectedProtocols.includes(server.type));
            }
        });

        const i18n = window.i18n;
        const tableHtml = `
            <div class="table-responsive m-0 p-0">
                <table class="table table-dark mb-0 providers-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">
                                <input type="checkbox" class="form-check-input" id="selectAllCheckbox">
                            </th>
                            <th>${i18n ? i18n.t('providers.provider') : 'Provider'}</th>
                            <th>${i18n ? i18n.t('providers.protocol') : 'Protocol'}</th>
                            <th>${i18n ? i18n.t('providers.address') : 'Address'}</th>
                            <th>${i18n ? i18n.t('providers.port') : 'Port'}</th>
                        </tr>
                    </thead>
                    ${this.generateTableRows(filteredProviders, selectedProtocols)}
                </table>
            </div>
        `;

        container.innerHTML = tableHtml;

        document.querySelectorAll('.provider-checkbox, .group-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => this.toggleProvider(e.target));
        });

        document.querySelectorAll('.folder-toggle').forEach(icon => {
            icon.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const providerName = e.target.dataset.provider;
                this.toggleGroupExpansion(providerName);
            });
        });

        document.querySelectorAll('.edit-custom-provider').forEach(button => {
            button.addEventListener('click', (e) => {
                const index = parseInt(e.target.closest('.edit-custom-provider').dataset.providerIndex);
                this.editCustomProvider(index);
            });
        });

        document.querySelectorAll('.delete-custom-provider').forEach(button => {
            button.addEventListener('click', (e) => {
                const index = parseInt(e.target.closest('.delete-custom-provider').dataset.providerIndex);
                this.deleteCustomProvider(index);
            });
        });

        const selectAllCheckbox = document.getElementById('selectAllCheckbox');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.selectAllProviders();
                } else {
                    this.deselectAllProviders();
                }
            });
        }

        this.updateProviderCount();
        this.updateSelectAllCheckbox();
    }

    generateTableRows(filteredProviders, selectedProtocols) {
        let rows = '';

        filteredProviders.forEach((provider, providerIndex) => {
            if (provider.isMainProvider) {
                rows += this.generateMainProviderRows(provider, selectedProtocols);
            } else if (!provider.isSubGroup) {
                rows += this.generateSimpleProviderRows(provider, selectedProtocols);
            }
        });

        return rows;
    }

    generateMainProviderRows(provider, selectedProtocols) {
        const isMainSelected = this.selectedProviders.some(p => p.name === provider.name);
        const isExpanded = this.expandedGroups.has(provider.name);
        const folderIcon = isExpanded ? 'bi-folder2-open' : 'bi-folder2';

        let bodies = '';

        bodies += `
            <tbody class="provider-block${isMainSelected ? ' is-selected' : ''}">
                <tr>
                    <td class="align-middle">
                        <input class="form-check-input provider-checkbox"
                               type="checkbox"
                               id="provider-${provider.name.replace(/\s+/g, '-')}"
                               data-provider="${provider.name}"
                               data-is-main="true"
                               ${isMainSelected ? 'checked' : ''}>
                    </td>
                    <td class="align-middle fw-bold">
                        <div class="d-flex align-items-center">
                            <i class="bi ${folderIcon} me-2 text-warning folder-toggle"
                               style="cursor: pointer;"
                               data-provider="${provider.name}"
                               title="${isExpanded ? 'Collapse' : 'Expand'} group"></i>
                            <span>${provider.name}</span>
                            <small class="text-muted ms-2">(${provider.groups.length} ${window.i18n ? window.i18n.t('providers.groups') : 'groups'})</small>
                        </div>
                    </td>
                    <td colspan="3" class="text-muted">
                        ${window.i18n ? window.i18n.t('providers.selectAllGroups') : 'Select to test all groups'}
                    </td>
                </tr>
            </tbody>
        `;

        if (isExpanded) {
            provider.groups.forEach(group => {
                const filteredServers = group.servers.filter(server =>
                    selectedProtocols.includes(server.type)
                );

                if (filteredServers.length === 0) return;

                const isGroupSelected = this.selectedProviders.some(p => p.name === group.name);

                let groupRows = '';
                filteredServers.forEach((server, index) => {
                    const isFirstRow = index === 0;
                    const rowspan = isFirstRow ? filteredServers.length : 0;

                    groupRows += `
                        <tr class="group-row" data-parent="${provider.name}">
                            ${isFirstRow ? `
                                <td rowspan="${rowspan}" class="align-middle ps-4">
                                    <input class="form-check-input group-checkbox"
                                           type="checkbox"
                                           id="group-${group.name.replace(/\s+/g, '-')}"
                                           data-provider="${group.name}"
                                           data-parent="${provider.name}"
                                           ${isGroupSelected ? 'checked' : ''}>
                                </td>
                                <td rowspan="${rowspan}" class="align-middle ps-4">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-arrow-return-right me-2 text-muted"></i>
                                        <span>${group.groupName}</span>
                                    </div>
                                </td>
                            ` : ''}
                            <td>
                                <span class="badge ${this.getProtocolColor(server.type)}">${server.type}</span>
                            </td>
                            <td class="font-monospace">${server.address}</td>
                            <td>${server.port}</td>
                        </tr>
                    `;
                });

                bodies += `
                    <tbody class="provider-block${isGroupSelected ? ' is-selected' : ''}">
                        ${groupRows}
                    </tbody>
                `;
            });
        }

        return bodies;
    }

    generateSimpleProviderRows(provider, selectedProtocols) {
        const filteredServers = provider.servers.filter(server =>
            selectedProtocols.includes(server.type)
        );

        const isSelected = this.selectedProviders.some(p => p.name === provider.name);

        let rows = '';
        filteredServers.forEach((server, index) => {
            const isFirstRow = index === 0;
            const rowspan = isFirstRow ? filteredServers.length : 0;

            rows += `
                <tr>
                    ${isFirstRow ? `
                        <td rowspan="${rowspan}" class="align-middle">
                            <input class="form-check-input provider-checkbox"
                                   type="checkbox"
                                   id="provider-${provider.name.replace(/\s+/g, '-')}"
                                   data-provider="${provider.name}"
                                   ${isSelected ? 'checked' : ''}>
                        </td>
                        <td rowspan="${rowspan}" class="align-middle fw-semibold">
                            <div class="d-flex justify-content-between align-items-center">
                                <span>${provider.name}</span>
                                ${provider.isCustom ? `
                                    <div class="btn-group btn-group-sm">
                                        <button type="button" class="btn btn-outline-warning btn-sm edit-custom-provider"
                                                data-provider-index="${this.getCustomProviderIndex(provider.name)}"
                                                title="${window.i18n ? window.i18n.t('customProvider.edit') : 'Edit'}">
                                            <i class="bi bi-pencil"></i>
                                        </button>
                                        <button type="button" class="btn btn-outline-danger btn-sm delete-custom-provider"
                                                data-provider-index="${this.getCustomProviderIndex(provider.name)}"
                                                title="${window.i18n ? window.i18n.t('customProvider.delete') : 'Delete'}">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                ` : ''}
                            </div>
                        </td>
                    ` : ''}
                    <td>
                        <span class="badge ${this.getProtocolColor(server.type)}">${server.type}</span>
                    </td>
                    <td class="font-monospace">${server.address}</td>
                    <td>${server.port}</td>
                </tr>
            `;
        });

        return `<tbody class="provider-block${isSelected ? ' is-selected' : ''}">${rows}</tbody>`;
    }

    getProtocolColor(protocol) {
        const colors = {
            'IPv4': 'bg-primary',
            'IPv6': 'bg-info',
            'DoH': 'bg-success',
            'DoT': 'bg-warning text-dark',
            'DoQ': 'bg-danger'
        };
        return colors[protocol] || 'bg-secondary';
    }

    updateSelectAllCheckbox() {
        const selectAllCheckbox = document.getElementById('selectAllCheckbox');
        if (!selectAllCheckbox) return;

        const allCheckboxes = document.querySelectorAll('.provider-checkbox, .group-checkbox');
        const checkedCheckboxes = document.querySelectorAll('.provider-checkbox:checked, .group-checkbox:checked');

        if (checkedCheckboxes.length === 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        } else if (checkedCheckboxes.length === allCheckboxes.length) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.indeterminate = false;
        } else {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = true;
        }
    }

    renderPresetDomains() {
        const select = document.getElementById('presetDomains');
        if (!select || !this.testDomains) return;

        select.innerHTML = this.testDomains.map(domain =>
            `<option value="${domain}" selected>${domain}</option>`
        ).join('');
    }

    getSelectedProtocols() {
        return Array.from(document.querySelectorAll('.protocol-filter:checked'))
            .map(cb => cb.value);
    }



    filterProviders() {
        this.renderProviders();
    }

    toggleProvider(checkbox) {
        const providerName = checkbox.dataset.provider;
        const isMainProvider = checkbox.dataset.isMain === 'true';
        const parentProvider = checkbox.dataset.parent;
        
        if (isMainProvider) {
            this.toggleMainProvider(providerName, checkbox.checked);
        } else if (parentProvider) {
            this.toggleGroupProvider(providerName, parentProvider, checkbox.checked);
        } else {
            this.toggleSimpleProvider(providerName, checkbox.checked);
        }

        this.updateProviderCount();
        this.updateSelectAllCheckbox();
        this.updateUI();
        this.renderProviders();
    }

    toggleMainProvider(providerName, isChecked) {
        const mainProvider = this.providers.find(p => p.name === providerName && p.isMainProvider);
        if (!mainProvider) return;

        if (isChecked) {
            if (!this.selectedProviders.some(p => p.name === providerName)) {
                this.selectedProviders.push(mainProvider);
            }
            
            mainProvider.groups.forEach(group => {
                const groupProvider = this.providers.find(p => p.name === group.name);
                if (groupProvider && !this.selectedProviders.some(p => p.name === group.name)) {
                    this.selectedProviders.push(groupProvider);
                }
            });
        } else {
            this.selectedProviders = this.selectedProviders.filter(p => p.name !== providerName);
            
            mainProvider.groups.forEach(group => {
                this.selectedProviders = this.selectedProviders.filter(p => p.name !== group.name);
            });
        }
    }

    toggleGroupProvider(groupName, parentName, isChecked) {
        const groupProvider = this.providers.find(p => p.name === groupName);
        if (!groupProvider) return;

        if (isChecked) {
            if (!this.selectedProviders.some(p => p.name === groupName)) {
                this.selectedProviders.push(groupProvider);
            }
        } else {
            this.selectedProviders = this.selectedProviders.filter(p => p.name !== groupName);
            
            this.selectedProviders = this.selectedProviders.filter(p => p.name !== parentName);
        }
    }

    toggleSimpleProvider(providerName, isChecked) {
        const provider = this.providers.find(p => p.name === providerName);
        if (!provider) return;

        if (isChecked) {
            if (!this.selectedProviders.some(p => p.name === providerName)) {
                this.selectedProviders.push(provider);
            }
        } else {
            this.selectedProviders = this.selectedProviders.filter(p => p.name !== providerName);
        }
    }

    selectAllProviders() {
        const checkboxes = document.querySelectorAll('.provider-checkbox, .group-checkbox');
        checkboxes.forEach(cb => {
            if (!cb.checked) {
                cb.checked = true;
                const providerName = cb.dataset.provider;
                const isMainProvider = cb.dataset.isMain === 'true';
                const parentProvider = cb.dataset.parent;
                
                if (isMainProvider) {
                    this.toggleMainProvider(providerName, true);
                } else if (parentProvider) {
                    this.toggleGroupProvider(providerName, parentProvider, true);
                } else {
                    this.toggleSimpleProvider(providerName, true);
                }
            }
        });
        this.updateProviderCount();
        this.updateSelectAllCheckbox();
        this.updateUI();
        this.renderProviders();
    }

    deselectAllProviders() {
        const checkboxes = document.querySelectorAll('.provider-checkbox, .group-checkbox');
        checkboxes.forEach(cb => {
            if (cb.checked) {
                cb.checked = false;
            }
        });
        this.selectedProviders = [];
        this.updateProviderCount();
        this.updateSelectAllCheckbox();
        this.updateUI();
        this.renderProviders();
    }

    updateProviderCount() {
        const count = this.selectedProviders.length;
        const buttons = document.querySelectorAll('#selectAllProviders, #deselectAllProviders');
        buttons.forEach(btn => {
            const text = btn.querySelector('.provider-count');
            if (text) text.remove();

            if (count > 0) {
                const span = document.createElement('span');
                span.className = 'provider-count ms-1 badge bg-light text-dark';
                span.textContent = count;
                btn.appendChild(span);
            }
        });

        const chip = document.getElementById('selectedProvidersChip');
        if (chip) {
            chip.textContent = count;
            chip.classList.toggle('is-empty', count === 0);
        }
    }

    async startTest() {
        if (this.isTestRunning) return;

        const config = this.getTestConfiguration();
        const validation = this.validateConfiguration(config);

        if (!validation.valid) {
            alert(validation.message);
            return;
        }

        this.isTestRunning = true;
        this.updateUI();

        try {
            await dnsTester.startTest(config);
        } catch (error) {
            console.error('Test failed:', error);
            this.handleTestError(error.message);
        } finally {
            this.isTestRunning = false;
            this.updateUI();
        }
    }

    stopTest() {
        dnsTester.stopTest();
        this.isTestRunning = false;
        this.updateUI();
    }

    getTestConfiguration() {
        const usePresetDomains = document.getElementById('usePresetDomains').checked;
        const selectedPresetDomains = usePresetDomains ?
            Array.from(document.getElementById('presetDomains').selectedOptions).map(opt => opt.value) : [];
        const customDomains = document.getElementById('customDomains').value;
        const testInterval = parseFloat(document.getElementById('testInterval').value);
        const testCount = parseInt(document.getElementById('testCount').value);
        const selectedProtocols = this.getSelectedProtocols();
        const queryType = document.querySelector('input[name="queryType"]:checked')?.value || 'A';

        return {
            selectedProviders: this.selectedProviders,
            selectedProtocols,
            usePresetDomains,
            selectedPresetDomains,
            customDomains,
            testInterval,
            testCount,
            queryType
        };
    }

    validateConfiguration(config) {
        const i18n = window.i18n;

        if (config.selectedProviders.length === 0) {
            return { valid: false, message: i18n ? i18n.t('errors.noProvidersSelected') : 'Please select at least one DNS provider.' };
        }

        if (config.selectedProtocols.length === 0) {
            return { valid: false, message: 'Please select at least one DNS protocol type.' };
        }

        const hasTestDomains = (config.usePresetDomains && config.selectedPresetDomains.length > 0) ||
                              (config.customDomains && config.customDomains.trim());

        if (!hasTestDomains) {
            return { valid: false, message: i18n ? i18n.t('errors.noDomainsSelected') : 'Please select preset domains or enter custom domains to test.' };
        }

        if (config.testInterval < 0) {
            return { valid: false, message: 'Test interval must be 0 or greater.' };
        }

        if (config.testCount < 1 || config.testCount > 20) {
            return { valid: false, message: 'Number of tests must be between 1 and 20.' };
        }

        return { valid: true };
    }

    updateUI() {
        const startBtn = document.getElementById('startTest');
        const stopBtn = document.getElementById('stopTest');

        if (this.isTestRunning) {
            startBtn.classList.add('d-none');
            stopBtn.classList.remove('d-none');
        } else {
            startBtn.classList.remove('d-none');
            stopBtn.classList.add('d-none');
        }

        const navbar = document.querySelector('.navbar');
        if (navbar) navbar.classList.toggle('is-testing', this.isTestRunning);

        const configInputs = document.querySelectorAll('#testInterval, #testCount, #customDomains, #presetDomains, .protocol-filter, .provider-checkbox');
        configInputs.forEach(input => {
            input.disabled = this.isTestRunning;
        });
    }

    exportCSV() {
        resultsManager.exportResults('csv');
    }

    exportJSON() {
        resultsManager.exportResults('json');
    }

    clearResults() {
        const i18n = window.i18n;
        const message = i18n ? i18n.t('results.confirmClear') : 'Are you sure you want to clear all test results?';
        if (confirm(message)) {
            resultsManager.clearResults();
            dnsTester.clearResults();
        }
    }

    handleTestError(error) {
        console.error('Test error:', error);
        alert(`Test error: ${error}`);
        this.isTestRunning = false;
        this.updateUI();
    }

    async changeLanguage(langCode) {
        try {
            await window.i18n.setLanguage(langCode);
            this.updateLanguageDisplay(langCode);

            if (window.resultsManager) {
                window.resultsManager.updateTranslations();
            }

            localStorage.setItem('selectedLanguage', langCode);

            document.documentElement.lang = langCode;
        } catch (error) {
            console.error('Failed to change language:', error);
        }
    }

    updateLanguageDisplay(langCode) {
        const languageNames = {
            'en': 'English',
            'zh': '中文 (简体)',
            'hi': 'हिन्दी',
            'es': 'Español',
            'fr': 'Français',
            'pt': 'Português',
            'pt-br': 'Português (BR)',
            'ru': 'Русский',
            'de': 'Deutsch',
            'it': 'Italiano',
            'ja': '日本語',
            'ko': '한국어'
        };

        const currentLanguageSpan = document.getElementById('currentLanguage');
        if (currentLanguageSpan) {
            currentLanguageSpan.textContent = languageNames[langCode] || 'English';
        }
    }

    loadSavedLanguage() {
        const savedLanguage = localStorage.getItem('selectedLanguage');
        if (savedLanguage && ['en', 'pt-BR', 'fr'].includes(savedLanguage)) {
            this.changeLanguage(savedLanguage);
        }
    }

    addCustomProvider() {
        if (window.customProvidersManager) {
            window.customProvidersManager.showAddProviderModal();
        }
    }

    editCustomProvider(index) {
        if (window.customProvidersManager) {
            window.customProvidersManager.showEditProviderModal(index);
        }
    }

    deleteCustomProvider(index) {
        if (window.customProvidersManager) {
            const i18n = window.i18n;
            const message = i18n ? i18n.t('customProvider.confirmDelete') : 'Are you sure you want to delete this custom provider?';
            if (confirm(message)) {
                const result = window.customProvidersManager.deleteProvider(index);
                if (result.success) {
                    this.refreshProviders();
                }
            }
        }
    }

    getCustomProviderIndex(providerName) {
        if (window.customProvidersManager) {
            const customProviders = window.customProvidersManager.getCustomProviders();
            return customProviders.findIndex(p => p.name === providerName);
        }
        return -1;
    }

    toggleGroupExpansion(providerName) {
        if (this.expandedGroups.has(providerName)) {
            this.expandedGroups.delete(providerName);
        } else {
            this.expandedGroups.add(providerName);
        }
        this.renderProviders();
    }

    expandAllGroups() {
        // Find all main providers with groups
        this.providers.forEach(provider => {
            if (provider.isMainProvider && provider.groups && provider.groups.length > 0) {
                this.expandedGroups.add(provider.name);
            }
        });
        this.renderProviders();
    }

    collapseAllGroups() {
        this.expandedGroups.clear();
        this.renderProviders();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new YADNSBApp();
});