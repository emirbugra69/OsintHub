const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    // Temel sorgular
    checkUsername: (username) => ipcRenderer.invoke('check-username', username),
    checkEmail: (email) => ipcRenderer.invoke('check-email', email),
    checkPhone: (phone) => ipcRenderer.invoke('check-phone', phone),
    checkDomain: (domain) => ipcRenderer.invoke('check-domain', domain),
    checkWayback: (domain) => ipcRenderer.invoke('check-wayback', domain),

    // IP
    getMyIP: () => ipcRenderer.invoke('get-my-ip'),
    getIPLocation: (ip) => ipcRenderer.invoke('get-ip-location', ip),
    getDetailedIP: (ip) => ipcRenderer.invoke('get-detailed-ip-location', ip),

    // DNS & Subdomain
    getDNSHistory: (domain) => ipcRenderer.invoke('get-dns-history', domain),
    getIPFromDomain: (domain) => ipcRenderer.invoke('get-ip-from-domain', domain),
    getCRTSubdomains: (domain) => ipcRenderer.invoke('get-crt-subdomains', domain),

    // Port, Metadata, Fake User, Report
    scanPorts: (ip) => ipcRenderer.invoke('scan-ports', ip),
    analyzeMetadata: (imagePath) => ipcRenderer.invoke('analyze-metadata', imagePath),
    generateFakeUser: () => ipcRenderer.invoke('generate-fake-user'),
    saveReport: (data, filename) => ipcRenderer.invoke('save-report', data, filename),
    calculateScore: (results) => ipcRenderer.invoke('calculate-score', results),

    // History & Correlation
    getHistory: () => ipcRenderer.invoke('get-history'),
    clearHistory: () => ipcRenderer.invoke('clear-history'),
    addToHistory: (entry) => ipcRenderer.invoke('add-to-history', entry),
    addToCorrelation: (type, value, source) => ipcRenderer.invoke('add-to-correlation', type, value, source),
    getCorrelationReport: () => ipcRenderer.invoke('get-correlation-report'),

    // Graph & Dashboard
    getGraphData: () => ipcRenderer.invoke('get-graph-data'),
    getRiskDashboard: () => ipcRenderer.invoke('get-risk-dashboard'),

    // Proxy
    setProxy: (proxyUrl) => ipcRenderer.invoke('set-proxy', proxyUrl),
    getProxy: () => ipcRenderer.invoke('get-proxy'),
    clearProxy: () => ipcRenderer.invoke('clear-proxy'),

    // Batch
    batchUsername: (usernames) => ipcRenderer.invoke('batch-username', usernames),
    batchDomain: (domains) => ipcRenderer.invoke('batch-domain', domains),
    setBatchConcurrency: (concurrency) => ipcRenderer.invoke('set-batch-concurrency', concurrency),

    // Kurumsal / Adli / VIP / Typosquatting
    checkTyposquatting: (domain) => ipcRenderer.invoke('check-typosquatting', domain),
    checkEmployeeLeaks: (domain) => ipcRenderer.invoke('check-employee-leaks', domain),
    vipProtectionScan: (name, email) => ipcRenderer.invoke('vip-protection-scan', name, email),
    saveForensicReport: (data, caseName) => ipcRenderer.invoke('save-forensic-report', data, caseName),
    generatePDFReport: (data, filename) => ipcRenderer.invoke('generate-pdf-report', data, filename),
    getEULA: () => ipcRenderer.invoke('get-eula'),
    generateHtmlReport: (data) => ipcRenderer.invoke('generate-html-report', data)
});