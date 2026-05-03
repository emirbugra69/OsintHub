const { app, BrowserWindow, ipcMain, dialog, Tray, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const { promisify } = require('util');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const ExifParser = require('exif-parser');
require('dotenv').config();

// --- DÜZELTİLMİŞ IMPORTLAR ---
const PQueueModule = require('p-queue');
const PQueue = PQueueModule.default ? PQueueModule.default : PQueueModule;

const PDFDocumentModule = require('pdfkit');
const PDFDocument = PDFDocumentModule.default ? PDFDocumentModule.default : PDFDocumentModule;

const libphonenumber = require('libphonenumber-js');
const parsePhoneNumberFromString = libphonenumber.parsePhoneNumberFromString || libphonenumber.default?.parsePhoneNumberFromString;

const dnsLookup = promisify(dns.lookup);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveNs = promisify(dns.resolveNs);

// ============ KONFİGÜRASYON ============
const CONFIG = {
    BATCH_CONCURRENCY: 3,
    GLOBAL_TIMEOUT: 15000,
    RATE_LIMIT_MAX_CALLS: 5,
    RATE_LIMIT_WINDOW_MS: 10000,
    API_KEYS: {
        IPINFO: process.env.IPINFO_TOKEN || '',
        LEAKCHECK: process.env.LEAKCHECK_API_KEY || ''
    },
    VERSION: '2.1.0',
    UPDATE_URL: 'https://raw.githubusercontent.com/emirbugra69/OsintHub/main/version.json'
};

if (!process.env.IPINFO_TOKEN) {
    console.warn('⚠️ IPINFO_TOKEN .env dosyasında bulunamadı, detaylı IP lokasyonu sınırlı çalışabilir.');
}
if (!process.env.LEAKCHECK_API_KEY) {
    console.warn('⚠️ LEAKCHECK_API_KEY .env dosyasında bulunamadı, email breach kontrolü çalışmayabilir.');
}

// ============ PROXY DÜZELTİLDİ ============
let activeProxy = null;
let mainWindow = null;
let tray = null;

// FIX: Dinamik axios instance oluşturma
let axiosInstance = axios.create({
    timeout: CONFIG.GLOBAL_TIMEOUT,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
});

function createAxiosInstance() {
    const config = {
        timeout: CONFIG.GLOBAL_TIMEOUT,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    };
    if (activeProxy) {
        if (activeProxy.startsWith('socks')) {
            config.httpsAgent = new SocksProxyAgent(activeProxy);
            config.httpAgent = new SocksProxyAgent(activeProxy);
        } else {
            config.httpAgent = new HttpProxyAgent(activeProxy);
            config.httpsAgent = new HttpsProxyAgent(activeProxy);
        }
    }
    axiosInstance = axios.create(config);
}

function setProxy(proxyUrl) {
    const validProxy = /^(socks5?|https?):\/\/.+:\d+$/.test(proxyUrl);
    if (!validProxy) return { success: false, error: 'Geçersiz proxy formatı. Örnek: socks5://127.0.0.1:9050' };
    activeProxy = proxyUrl;
    createAxiosInstance(); // FIX: yeni instance oluştur
    return { success: true, proxy: proxyUrl };
}

function clearProxy() {
    activeProxy = null;
    createAxiosInstance();
    return { success: true };
}

async function proxyGet(url, extraConfig = {}) {
    return axiosInstance.get(url, extraConfig);
}

// ============ HISTORY (ASYNC YAZMA) ============
const historyPath = path.join(app.getPath('userData'), 'history.json');
let history = [];
function loadHistoryFromDisk() { try { if (fs.existsSync(historyPath)) history = JSON.parse(fs.readFileSync(historyPath, 'utf8')); } catch(e) {} }
async function saveHistoryToDisk() { 
    try { 
        await fs.promises.writeFile(historyPath, JSON.stringify(history.slice(-100), null, 2)); 
    } catch(e) {} 
}
function addToHistoryInternal(entry) { 
    entry.timestamp = new Date().toISOString(); 
    history.unshift(entry); 
    if (history.length > 100) history.pop(); 
    saveHistoryToDisk(); 
}

// ============ RATE LIMIT ============
const rateLimitMap = new Map();
function checkRateLimit(key, maxCalls = CONFIG.RATE_LIMIT_MAX_CALLS, windowMs = CONFIG.RATE_LIMIT_WINDOW_MS) {
    const now = Date.now();
    if (!rateLimitMap.has(key)) rateLimitMap.set(key, []);
    const timestamps = rateLimitMap.get(key).filter(t => now - t < windowMs);
    if (timestamps.length >= maxCalls) return false;
    timestamps.push(now);
    rateLimitMap.set(key, timestamps);
    return true;
}
function sanitizeInput(input) { if (typeof input !== 'string') return ''; return input.trim().substring(0, 200); }

// ============ BATCH CONCURRENCY (FIX) ============
let currentConcurrency = CONFIG.BATCH_CONCURRENCY;
let batchQueue = new PQueue({ concurrency: currentConcurrency, interval: 1000, intervalCap: currentConcurrency });

// FIX: concurrency değişince queue'yu yeniden oluşturma, sadece property'yi değiştir
async function setBatchConcurrency(newConcurrency) {
    if (newConcurrency >= 1 && newConcurrency <= 10) {
        currentConcurrency = newConcurrency;
        batchQueue.concurrency = currentConcurrency; // P-queue property
        return { success: true, concurrency: currentConcurrency };
    }
    return { success: false, error: 'Concurrency 1-10 arasında olmalıdır.' };
}

// ============ GELİŞMİŞ FORENSIC RAPOR ============
function calculateConfidence(finding) {
    let confidence = 50;
    if (finding.source === 'leakcheck' && finding.breached) confidence += 30;
    if (finding.source === 'dns') confidence += 20;
    if (finding.source === 'ip-api') confidence += 15;
    if (finding.value && finding.value.includes('@')) confidence += 10;
    if (finding.value && /^\d+\.\d+\.\d+\.\d+$/.test(finding.value)) confidence += 10;
    if (finding.duplicateCount > 1) confidence += 10;
    return Math.min(100, confidence);
}

function generateForensicReport(findings, caseNumber = 'OSINT-001', investigator = 'OsintHub User') {
    const timestamp = new Date().toISOString();
    const reportId = crypto.randomBytes(16).toString('hex');
    const reportHash = crypto.createHash('sha256').update(JSON.stringify(findings) + timestamp + reportId).digest('hex');

    const timeline = [];
    for (const f of findings) {
        timeline.push({
            timestamp: f.timestamp || timestamp,
            source: f.source || 'manual',
            type: f.type || 'unknown',
            value: f.value,
            confidence: f.confidence || calculateConfidence(f),
            description: f.description || `${f.type} bilgisi toplandı`
        });
    }
    timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const stats = {
        totalFindings: findings.length,
        byType: {},
        avgConfidence: 0,
        highConfidenceCount: 0,
        uniqueSources: [...new Set(timeline.map(t => t.source))]
    };
    let totalConf = 0;
    for (const f of findings) {
        const type = f.type || 'unknown';
        stats.byType[type] = (stats.byType[type] || 0) + 1;
        const conf = f.confidence || calculateConfidence(f);
        totalConf += conf;
        if (conf >= 80) stats.highConfidenceCount++;
    }
    stats.avgConfidence = findings.length ? (totalConf / findings.length).toFixed(1) : 0;

    return {
        caseId: caseNumber,
        reportId: reportId,
        generatedAt: timestamp,
        generatedBy: investigator,
        chainOfCustody: {
            created: timestamp,
            creator: investigator,
            hash: reportHash,
            hashAlgorithm: 'SHA-256',
            source: 'OsintHub Forensic Module v2.0'
        },
        summary: {
            totalFindings: stats.totalFindings,
            averageConfidence: stats.avgConfidence + '%',
            highConfidenceFindings: stats.highConfidenceCount,
            uniqueDataSources: stats.uniqueSources.length
        },
        timeline: timeline,
        findingsByType: stats.byType,
        rawFindings: findings,
        verification: {
            reportIntegrity: reportHash,
            verifyCommand: `sha256sum ${caseNumber}_${reportId.substring(0, 8)}.json`
        },
        disclaimer: "Bu rapor OsintHub Forensic Module tarafından otomatik oluşturulmuştur. Delil olarak kullanılmadan önce doğrulanmalıdır."
    };
}

async function saveForensicReport(data, caseName) {
    try {
        if (!caseName || typeof caseName !== 'string') return { success: false, error: 'Geçersiz dosya adı' };
        const dataStr = JSON.stringify(data);
        if (dataStr.length > 5 * 1024 * 1024) return { success: false, error: 'Veri çok büyük (max 5MB)' };

        const desktop = path.join(require('os').homedir(), 'Desktop');
        if (!fs.existsSync(desktop)) throw new Error('Masaüstü bulunamadı');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const safeName = caseName.replace(/[^a-zA-Z0-9_\-]/g, '_');
        const filename = `forensic_${safeName}_${timestamp}.json`;

        const filePath = path.resolve(desktop, filename);
        if (!filePath.startsWith(path.resolve(desktop))) return { success: false, error: 'Geçersiz dosya yolu' };

        const forensicData = generateForensicReport(Array.isArray(data) ? data : [data], caseName);
        await fs.promises.writeFile(filePath, JSON.stringify(forensicData, null, 2));
        return { success: true, path: filePath, hash: forensicData.chainOfCustody.hash, reportId: forensicData.reportId };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

async function generatePDFReport(data, filename) {
    try {
        const desktop = path.join(require('os').homedir(), 'Desktop');
        if (!fs.existsSync(desktop)) throw new Error('Masaüstü bulunamadı');
        const safeFilename = filename.replace(/[^a-zA-Z0-9_\-]/g, '_');

        const filePath = path.resolve(desktop, `${safeFilename}.pdf`);
        if (!filePath.startsWith(path.resolve(desktop))) return { success: false, error: 'Geçersiz dosya yolu' };

        const doc = new PDFDocument();
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);
        doc.fontSize(20).text('Adli Analiz Raporu', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Rapor Tarihi: ${new Date().toISOString()}`);
        doc.text(`SHA-256: ${crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex').substring(0, 32)}...`);
        doc.moveDown();
        doc.text(JSON.stringify(data, null, 2), { width: 500 });
        doc.end();
        return new Promise((resolve) => {
            stream.on('finish', () => resolve({ success: true, path: filePath }));
            stream.on('error', (e) => resolve({ success: false, error: e.message }));
        });
    } catch (e) {
        return { success: false, error: e.message };
    }
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function generateHTMLReport(data) {
    const safeData = escapeHtml(JSON.stringify(data, null, 2));
    return `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>OsintHub Analiz Raporu</title>
        <style>
            body { background: #0a0e27; color: #00ff88; font-family: monospace; padding: 20px; }
            h1 { color: #00ff88; border-bottom: 1px solid #00ff88; }
            pre { background: #1a1a2e; padding: 15px; border-radius: 10px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🕵️ OsintHub Analiz Raporu</h1>
        <p>Oluşturulma Tarihi: ${escapeHtml(new Date().toLocaleString())}</p>
        <pre>${safeData}</pre>
    </body>
    </html>`;
}

// ============ KURUMSAL MODÜLLER (SSRF FIX) ============
// FIX: Domain validasyonu
function isValidDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    return domainRegex.test(domain);
}

async function checkTyposquatting(domain) {
    if (!isValidDomain(domain)) return { originalDomain: domain, typosquattingDomains: [], totalActive: 0, error: 'Geçersiz domain formatı' };
    const base = domain.replace(/\.[^.]+$/, '');
    const tld = domain.includes('.') ? domain.split('.').pop() : 'com';
    const typos = [
        base + '.' + tld,
        base.replace(/[aeiou]/g, c => ({ a:'4',e:'3',i:'1',o:'0',u:'v' }[c] || c)) + '.' + tld,
        base.replace('c', 'k') + '.' + tld,
        base.replace('e', '3') + '.' + tld,
        base + '.net', base + '.org', base + '.co',
        base + '-secure.' + tld, base + '-login.' + tld,
        base.split('').join('-') + '.' + tld,
    ].filter(v => v !== domain);

    const variations = [];
    for (const typo of [...new Set(typos)].slice(0, 10)) {
        try {
            await proxyGet(`https://${typo}`, { timeout: 5000 });
            variations.push({ domain: typo, active: true, risk: 'PHISHING RİSKİ' });
        } catch(e) {
            variations.push({ domain: typo, active: false, risk: 'Düşük' });
        }
    }
    return { originalDomain: domain, typosquattingDomains: variations, totalActive: variations.filter(v => v.active).length };
}

async function checkEmployeeLeaks(domain) {
    if (!isValidDomain(domain)) return { domain, totalLeaked: 0, leakedEmails: [], error: 'Geçersiz domain' };
    const commonEmails = ['admin', 'info', 'support', 'sales', 'contact', 'ceo', 'hr', 'it', 'cto', 'billing', 'noreply', 'security', 'abuse', 'webmaster'];
    const leaked = [];
    for (const email of commonEmails) {
        const fullEmail = `${email}@${domain}`;
        try {
            const response = await proxyGet(`https://leakcheck.net/api/public?check=${encodeURIComponent(fullEmail)}`, { timeout: 8000 });
            if (response.data && response.data.found) leaked.push({ email: fullEmail, sources: response.data.sources || ['Bilinmeyen'] });
        } catch(e) {}
        await new Promise(r => setTimeout(r, 200));
    }
    return { domain, totalLeaked: leaked.length, leakedEmails: leaked, riskLevel: leaked.length > 2 ? 'YÜKSEK' : (leaked.length > 0 ? 'ORTA' : 'DÜŞÜK') };
}

async function vipProtectionScan(name, email) {
    const findings = [];
    if (email) { const e = await checkEmail(email); findings.push({ type: 'Email', value: email, breached: e.breached, sources: e.sources || [] }); }
    if (name) { const ns = await checkUsername(name.toLowerCase().replace(/\s/g, '')); findings.push({ type: 'Username', value: name, foundCount: ns.foundCount, platforms: ns.results.filter(r => r.exists).map(r => r.platform) }); }
    const riskScore = Math.min(100, findings.reduce((s, f) => s + (f.breached ? 45 : (f.foundCount > 3 ? 25 : 5)), 0));
    return {
        targetName: name, targetEmail: email, riskScore,
        riskLevel: riskScore >= 75 ? 'KRİTİK' : (riskScore >= 50 ? 'YÜKSEK' : (riskScore >= 25 ? 'ORTA' : 'DÜŞÜK')),
        findings,
        recommendations: [
            riskScore >= 75 ? 'Derhal tüm hesapları güvence altına alın' : 'Sosyal medya gizlilik ayarlarını kontrol edin',
            'Kişisel bilgilerin internette dolaşımını sınırlayın',
            'Düzenli OSINT taraması yapın'
        ].filter(r => r)
    };
}

function getEULA() {
    return {
        title: 'OsintHub - Kullanıcı Sözleşmesi', version: '2.0.0', lastUpdated: '2026-01-01',
        clauses: [
            'Bu araç yalnızca EĞİTİM ve SİBER GÜVENLİK ARAŞTIRMASI amaçlıdır.',
            'Kullanıcı, bu aracı kullanarak elde ettiği verilerin yasal sorumluluğunu tamamen kabul eder.',
            'Hedef alınan kişi veya kurumlardan YAZILI İZİN alınmadan kullanılması YASA DIŞIDIR.',
            'TCK 243-245 uyarınca izinsiz erişim ve veri toplama suçtur.',
            'Bu aracın kötüye kullanımından GELİŞTİRİCİ SORUMLU DEĞİLDİR.'
        ],
        acceptRequired: true
    };
}

// ============ CORRELATION ENGINE ============
class CorrelationEngine {
    constructor() { this.data = { usernames: [], emails: [], phones: [], domains: [], ips: [] }; this.correlations = []; }
    addData(type, value, source) {
        const key = type + 's';
        if (!this.data[key]) this.data[key] = [];
        const exists = this.data[key].some(item => item.value === value);
        if (!exists) this.data[key].push({ value, source, timestamp: Date.now() });
        this.analyzeCorrelations();
    }
    analyzeCorrelations() {
        this.correlations = [];
        const seen = new Set();
        for (const u of this.data.usernames) for (const e of this.data.emails) {
            if (u.value.toLowerCase() === e.value.split('@')[0].toLowerCase()) {
                const key = `username-email:${u.value}:${e.value}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    this.correlations.push({ type: 'username-email', confidence: 85, reason: `"${u.value}" email ile eşleşiyor` });
                }
            }
        }
        for (const e of this.data.emails) for (const p of this.data.phones) {
            if (e.source === p.source) {
                const key = `email-phone:${e.value}:${p.value}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    this.correlations.push({ type: 'email-phone', confidence: 60, reason: `Email ve Telefon aynı kaynakta (${e.source}) görüldü.` });
                }
            }
        }
        for (const d of this.data.domains) for (const i of this.data.ips) {
            if (d.source === 'dns' && i.source === 'dns') {
                const key = `domain-ip:${d.value}:${i.value}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    this.correlations.push({ type: 'domain-ip', confidence: 70, reason: `${d.value} → ${i.value} DNS bağlantısı` });
                }
            }
        }
    }
    getOverallRisk() {
        let risk = 50;
        for (const c of this.correlations) risk += c.confidence > 70 ? 10 : (c.confidence > 50 ? 5 : 0);
        risk = Math.min(100, risk);
        return { score: risk, level: risk >= 80 ? 'Yüksek Risk' : (risk >= 50 ? 'Orta Risk' : 'Düşük Risk') };
    }
    generateReport() {
        const risk = this.getOverallRisk();
        return {
            timestamp: new Date().toISOString(),
            summary: { totalFindings: Object.values(this.data).reduce((s, a) => s + a.length, 0), correlationsFound: this.correlations.length, riskScore: risk.score, riskLevel: risk.level },
            findings: { usernames: this.data.usernames.map(u => u.value), emails: this.data.emails.map(e => e.value), phones: this.data.phones.map(p => p.value), domains: this.data.domains.map(d => d.value), ips: this.data.ips.map(i => i.value) },
            correlations: this.correlations
        };
    }
}
const correlationEngine = new CorrelationEngine();

function getGraphData() {
    const r = correlationEngine.generateReport();
    const nodes = [], edges = [], set = new Set();
    const add = (id, label, type) => { if (!set.has(id)) { set.add(id); nodes.push({ data: { id, label, type } }); } };
    for (const u of r.findings.usernames) add(`u_${u}`, u, 'username');
    for (const e of r.findings.emails) add(`e_${e}`, e, 'email');
    for (const p of r.findings.phones) add(`p_${p}`, p, 'phone');
    for (const d of r.findings.domains) add(`d_${d}`, d, 'domain');
    for (const i of r.findings.ips) add(`i_${i}`, i, 'ip');
    for (const c of r.correlations) {
        if (c.type === 'username-email') {
            const u = r.findings.usernames.find(x => c.reason.includes(x));
            const e = r.findings.emails.find(x => c.reason.includes(x));
            if (u && e) edges.push({ data: { source: `u_${u}`, target: `e_${e}`, label: `${c.confidence}% güven` } });
        }
    }
    return { nodes, edges };
}

function getRiskDashboard() {
    const r = correlationEngine.generateReport();
    const cats = { high: r.correlations.filter(c => c.confidence >= 70).length, medium: r.correlations.filter(c => c.confidence >= 50 && c.confidence < 70).length, low: r.correlations.filter(c => c.confidence < 50).length };
    const threats = [];
    if (r.findings.emails.length) threats.push('Veri ihlali');
    if (r.correlations.length > 2) threats.push('Güçlü bağlantılar');
    return { riskScore: r.summary.riskScore, riskLevel: r.summary.riskLevel, riskCategories: cats, activeThreats: threats, totalFindings: r.summary.totalFindings, recentActivity: history.length, topFindings: { usernames: r.findings.usernames.slice(0, 5), emails: r.findings.emails.slice(0, 5) } };
}

// ============ BATCH SORGU (HATA YÖNETİMİ FIX) ============
async function batchUsernameSearch(usernames) {
    const results = [];
    const promises = usernames.filter(u => u.trim()).map(async (u) => batchQueue.add(async () => {
        try {
            const r = await checkUsername(u.trim());
            return { username: u.trim(), foundCount: r.foundCount, platforms: r.results.filter(x => x.exists).map(x => x.platform) };
        } catch (err) {
            return { username: u.trim(), error: err.message };
        }
    }));
    const settled = await Promise.allSettled(promises);
    for (const p of settled) {
        if (p.status === 'fulfilled') results.push(p.value);
        else results.push({ error: p.reason?.message || 'Unknown error' });
    }
    return results;
}
async function batchDomainSearch(domains) {
    const results = [];
    const promises = domains.filter(d => d.trim()).map(async (d) => batchQueue.add(async () => {
        try {
            const r = await checkDomain(d.trim());
            return { domain: d.trim(), ip: r.results.ip };
        } catch (err) {
            return { domain: d.trim(), error: err.message };
        }
    }));
    const settled = await Promise.allSettled(promises);
    for (const p of settled) {
        if (p.status === 'fulfilled') results.push(p.value);
        else results.push({ error: p.reason?.message || 'Unknown error' });
    }
    return results;
}

// ============ USERNAME ============
async function checkUsername(username) {
    const platforms = {
        'GitHub':    { url: `https://github.com/${username}`,             notFound: ['not found', '404', 'page not found'] },
        'Twitter':   { url: `https://twitter.com/${username}`,            notFound: ['this account doesn\'t exist', 'page not found', '404'] },
        'Instagram': { url: `https://instagram.com/${username}`,          notFound: ['page not found', 'sorry, this page', '404'] },
        'Reddit':    { url: `https://reddit.com/user/${username}`,        notFound: ['page not found', 'sorry, nobody on reddit', '404'] },
        'YouTube':   { url: `https://youtube.com/@${username}`,           notFound: ['404', 'page not found', 'this page isn\'t available'] },
        'Twitch':    { url: `https://twitch.tv/${username}`,              notFound: ['page not found', '404', 'sorry. unless you\'ve'] },
        'Pinterest': { url: `https://pinterest.com/${username}`,          notFound: ['404', 'page not found', 'user not found'] },
        'TikTok':    { url: `https://tiktok.com/@${username}`,            notFound: ['couldn\'t find this account', '404', 'page not found'] },
        'Facebook':  { url: `https://facebook.com/${username}`,           notFound: ['page not found', 'content not found', '404'] },
        'LinkedIn':  { url: `https://linkedin.com/in/${username}`,        notFound: ['page not found', 'profile not found', '404'] },
        'Medium':    { url: `https://medium.com/@${username}`,            notFound: ['page not found', '404', 'user not found'] },
        'GitLab':    { url: `https://gitlab.com/${username}`,             notFound: ['page not found', '404', 'the page you\'re looking for'] },
        'Snapchat':  { url: `https://snapchat.com/add/${username}`,       notFound: ['page not found', '404'] },
        'Telegram':  { url: `https://t.me/${username}`,                   notFound: ['page not found', 'tgme_page_wrap', 'if you have telegram'] },
        'Spotify':   { url: `https://open.spotify.com/user/${username}`,  notFound: ['page not found', '404', 'page doesn\'t exist'] }
    };
    const results = []; let found = 0;
    for (const [platform, cfg] of Object.entries(platforms)) {
        try {
            const res = await proxyGet(cfg.url, { timeout: 8000 });
            const body = (res.data || '').toString().toLowerCase();
            if (res.status === 200 && !cfg.notFound.some(p => body.includes(p))) {
                found++; results.push({ platform, url: cfg.url, exists: true });
                correlationEngine.addData('username', username, platform);
            } else results.push({ platform, url: cfg.url, exists: false });
        } catch(e) { results.push({ platform, url: cfg.url, exists: false }); }
        await new Promise(r => setTimeout(r, 150));
    }
    addToHistoryInternal({ type: 'Username', query: username, result: `${found} platformda bulundu` });
    return { results, foundCount: found };
}

// ============ EMAIL, PHONE, DOMAIN, WAYBACK, CRT, IP, PORT, DNS ============
async function checkEmail(email) {
    try {
        const r = await proxyGet(`https://leakcheck.net/api/public?check=${encodeURIComponent(email)}`, { timeout: 15000 });
        if (r.data && r.data.found) {
            correlationEngine.addData('email', email, 'leakcheck');
            addToHistoryInternal({ type: 'Email', query: email, result: 'İhlal bulundu' });
            return { email, breached: true, sources: r.data.sources || [] };
        }
    } catch(e) {}
    correlationEngine.addData('email', email, 'leakcheck');
    addToHistoryInternal({ type: 'Email', query: email, result: 'Temiz' });
    return { email, breached: false, message: 'İhlal bulunamadı' };
}

// FIX: Buffer ile EXIF analizi (path yerine)
async function analyzeImageMetadataFromBuffer(buffer) {
    try {
        const parsed = ExifParser.create(buffer).parse();
        const e = parsed.tags || {};
        return {
            success: true,
            make: e.Make,
            model: e.Model,
            datetime: e.DateTimeOriginal,
            gps: e.GPSLatitude ? { lat: e.GPSLatitude, lon: e.GPSLongitude } : null,
            software: e.Software
        };
    } catch(e) { return { success: false, error: e.message }; }
}

// Eski path'li fonksiyonu da güvenli hale getirelim (opsiyonel)
async function analyzeImageMetadataFromPath(filePath) {
    try {
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif'];
        const ext = path.extname(filePath).toLowerCase();
        if (!allowedExtensions.includes(ext)) {
            return { success: false, error: 'Geçersiz dosya türü. Sadece JPG, PNG, TIFF desteklenir.' };
        }
        const resolvedPath = path.resolve(filePath);
        // FIX: Sadece Masaüstü ve Downloads gibi güvenli klasörlere izin ver
        const desktop = path.join(require('os').homedir(), 'Desktop');
        const downloads = path.join(require('os').homedir(), 'Downloads');
        if (!resolvedPath.startsWith(desktop) && !resolvedPath.startsWith(downloads)) {
            return { success: false, error: 'Dosya yolu güvenli değil. Sadece Masaüstü ve Downloads klasörlerine izin verilir.' };
        }
        if (!fs.existsSync(resolvedPath)) {
            return { success: false, error: 'Dosya bulunamadı.' };
        }
        const b = fs.readFileSync(resolvedPath);
        return analyzeImageMetadataFromBuffer(b);
    } catch(e) { return { success: false, error: e.message }; }
}

async function checkPhone(pn) {
    try {
        const parsed = parsePhoneNumberFromString(pn, 'TR');
        if (parsed && parsed.isValid()) {
            const f = parsed.formatInternational();
            correlationEngine.addData('phone', f, 'libphonenumber');
            addToHistoryInternal({ type: 'Telefon', query: pn, result: f });
            return { valid: true, international: f, national: parsed.formatNational(), countryCode: parsed.country };
        }
        return { valid: false, error: 'Geçersiz numara' };
    } catch(e) { return { valid: false, error: e.message }; }
}

async function checkDomain(domain) {
    const results = {};
    try { const l = await dnsLookup(domain); results.ip = l.address; correlationEngine.addData('domain', domain, 'dns'); correlationEngine.addData('ip', l.address, 'dns'); } catch(e) { results.ip = 'Bulunamadı'; }
    try { const mx = await dnsResolveMx(domain); results.mx = mx.slice(0, 3); } catch(e) { results.mx = []; }
    try { const ns = await dnsResolveNs(domain); results.ns = ns.slice(0, 3); } catch(e) { results.ns = []; }
    addToHistoryInternal({ type: 'Domain', query: domain, result: results.ip });
    return { domain, results };
}

async function checkWayback(domain) {
    try {
        const r = await proxyGet(`https://archive.org/wayback/available?url=${domain}`, { timeout: 15000 });
        if (r.data?.archived_snapshots?.closest?.url) {
            addToHistoryInternal({ type: 'Wayback', query: domain, result: 'Arşiv' });
            return { domain, archived: true, url: r.data.archived_snapshots.closest.url, timestamp: r.data.archived_snapshots.closest.timestamp };
        }
    } catch(e) {}
    addToHistoryInternal({ type: 'Wayback', query: domain, result: 'Yok' });
    return { domain, archived: false };
}

async function getCRTSubdomains(domain) {
    try {
        const r = await proxyGet(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 20000 });
        // FIX: Eğer dizi değilse veya hatalıysa boş dizi döndür
        let data = r.data;
        if (!Array.isArray(data)) {
            // JSON parse hatası olabilir, güvenli şekilde kontrol et
            if (typeof data === 'string') {
                try { data = JSON.parse(data); } catch(e) { data = []; }
            } else {
                data = [];
            }
        }
        if (Array.isArray(data)) {
            const subs = [...new Set(data.map(i => i.name_value).filter(Boolean).flatMap(v => v.split('\n')).map(v => v.trim().replace(/^\*\./, '')).filter(v => v.endsWith(domain)))].sort();
            addToHistoryInternal({ type: 'CRT', query: domain, result: `${subs.length}` });
            return { domain, subdomains: subs.slice(0, 50), total: subs.length };
        }
    } catch(e) {}
    return { domain, subdomains: [], total: 0, error: 'Subdomain bulunamadı' };
}

async function getMyIP() {
    try { const r = await proxyGet('https://api.ipify.org?format=json'); return { ip: r.data.ip, success: true }; }
    catch(e) { return { ip: 'Bulunamadı', success: false }; }
}

async function getIPLocation(ip) {
    try {
        const r = await proxyGet(`http://ip-api.com/json/${ip}`);
        if (r.data?.status === 'success') {
            correlationEngine.addData('ip', ip, 'ip-api');
            addToHistoryInternal({ type: 'IP', query: ip, result: `${r.data.country}` });
            return { success: true, ip: r.data.query, country: r.data.country, city: r.data.city, isp: r.data.isp, region: r.data.regionName, timezone: r.data.timezone, lat: r.data.lat, lon: r.data.lon };
        }
    } catch(e) {}
    return { success: false, error: 'Lokasyon alınamadı' };
}

async function getDetailedIPLocation(ip) {
    const token = CONFIG.API_KEYS.IPINFO;
    try {
        const url = token ? `https://ipinfo.io/${ip}?token=${token}` : `https://ipinfo.io/${ip}/json`;
        const r = await proxyGet(url, { timeout: 8000 });
        if (r.data && r.data.ip) {
            const d = r.data;
            const [lat, lon] = (d.loc || ',').split(',');
            correlationEngine.addData('ip', ip, 'ipinfo');
            addToHistoryInternal({ type: 'Detaylı IP', query: ip, result: `${d.country}` });
            return { success: true, ip: d.ip, country: d.country, city: d.city, region: d.region, org: d.org, postal: d.postal, timezone: d.timezone, hostname: d.hostname || 'Yok', lat, lon };
        }
    } catch(e) {}
    return await getIPLocation(ip);
}

async function scanPorts(ip) {
    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return { ip, openPorts: [], totalOpen: 0, error: 'Geçersiz IP formatı' };
    }
    const ports = [
        { port: 21, name: 'FTP' }, { port: 22, name: 'SSH' }, { port: 23, name: 'Telnet' },
        { port: 25, name: 'SMTP' }, { port: 53, name: 'DNS' }, { port: 80, name: 'HTTP' },
        { port: 110, name: 'POP3' }, { port: 143, name: 'IMAP' }, { port: 443, name: 'HTTPS' },
        { port: 445, name: 'SMB' }, { port: 3306, name: 'MySQL' }, { port: 3389, name: 'RDP' },
        { port: 5900, name: 'VNC' }, { port: 8080, name: 'HTTP-Alt' }, { port: 8443, name: 'HTTPS-Alt' }
    ];
    const open = [];
    await Promise.all(ports.map(p => new Promise((resolve) => {
        const s = new net.Socket();
        const t = setTimeout(() => { s.destroy(); resolve(); }, 2000);
        s.connect(p.port, ip, () => { clearTimeout(t); open.push(p); s.destroy(); resolve(); });
        s.on('error', () => { clearTimeout(t); resolve(); });
    })));
    addToHistoryInternal({ type: 'Port', query: ip, result: `${open.length} açık` });
    return { ip, openPorts: open, totalOpen: open.length };
}

async function getIPFromDomain(domain) {
    try {
        const l = await dnsLookup(domain);
        correlationEngine.addData('domain', domain, 'dns-resolve');
        correlationEngine.addData('ip', l.address, 'dns-resolve');
        addToHistoryInternal({ type: 'Domain→IP', query: domain, result: l.address });
        return { success: true, domain, ip: l.address };
    } catch(e) { return { success: false, error: 'IP bulunamadı' }; }
}

async function getDNSHistory(domain) {
    let res = {};
    try { res.current_ip = (await dnsLookup(domain)).address; } catch(e) { res.current_ip = 'Bulunamadı'; }
    try { res.mx = (await dnsResolveMx(domain)).slice(0, 5).map(m => m.exchange); } catch(e) { res.mx = []; }
    try { res.ns = (await dnsResolveNs(domain)).slice(0, 5); } catch(e) { res.ns = []; }
    addToHistoryInternal({ type: 'DNS', query: domain, result: res.current_ip });
    return { success: true, domain, ...res };
}

async function generateFakeUser() {
    const firstNames = ['Ali','Veli','Ayşe','Mehmet','Fatma','Hasan','Zeynep','Murat','Elif','Emre','Seda','Burak','Cansu','Tarık','Deniz'];
    const lastNames = ['Yılmaz','Demir','Kaya','Çelik','Şahin','Arslan','Doğan','Koç','Aydın','Özdemir'];
    const cities = ['İstanbul','Ankara','İzmir','Bursa','Antalya','Adana','Konya','Gaziantep','Mersin','Kayseri'];
    const domains = ['gmail.com','hotmail.com','yahoo.com','outlook.com'];
    const f = firstNames[Math.floor(Math.random() * firstNames.length)];
    const l = lastNames[Math.floor(Math.random() * lastNames.length)];
    const city = cities[Math.floor(Math.random() * cities.length)];
    const dom = domains[Math.floor(Math.random() * domains.length)];
    const num = Math.floor(Math.random() * 9000) + 1000;
    return { fullName: `${f} ${l}`, email: `${f.toLowerCase()}.${l.toLowerCase()}${num}@${dom}`, phone: `+905${Math.floor(Math.random()*90000000)+10000000}`, city, username: `${f.toLowerCase()}${l.toLowerCase()}${num}` };
}

async function saveReport(data, filename) {
    const desktop = path.join(require('os').homedir(), 'Desktop');
    const safe = filename.replace(/[^a-zA-Z0-9_\-]/g, '_');
    const fp = path.resolve(desktop, `${safe}.json`);
    if (!fp.startsWith(path.resolve(desktop))) return { success: false, error: 'Geçersiz dosya yolu' };
    try { await fs.promises.writeFile(fp, JSON.stringify(data, null, 2)); return { success: true, path: fp }; }
    catch(e) { return { success: false, error: e.message }; }
}

function calculateScore(results) {
    let s = 100;
    if (results.usernameFound > 5) s -= 20;
    if (results.emailBreached) s -= 35;
    if (results.openPorts > 3) s -= 15;
    if (results.subdomainCount > 10) s -= 10;
    s = Math.max(0, Math.min(100, s));
    return { score: s, level: s >= 80 ? 'Düşük Risk' : (s >= 50 ? 'Orta Risk' : 'Yüksek Risk'), risks: [] };
}

// ============ YENİ ÖZELLİKLER ============
function createTray() {
    const iconPath = path.join(__dirname, 'icon.ico');
    let trayIcon = null;
    if (fs.existsSync(iconPath)) trayIcon = iconPath;
    else trayIcon = path.join(__dirname, 'icon.ico');
    tray = new Tray(trayIcon);
    const contextMenu = Menu.buildFromTemplate([
        { label: 'Göster', click: () => { if (mainWindow) mainWindow.show(); } },
        { label: 'Gizle', click: () => { if (mainWindow) mainWindow.hide(); } },
        { type: 'separator' },
        { label: 'Çıkış', click: () => app.quit() }
    ]);
    tray.setToolTip('OsintHub');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => {
        if (mainWindow) mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
    });
}

async function checkForUpdates() {
    try {
        const response = await axios.get(CONFIG.UPDATE_URL, { timeout: 5000 });
        const latest = response.data;
        if (latest.version && latest.version !== CONFIG.VERSION) {
            const result = await dialog.showMessageBox({
                type: 'info',
                title: 'Güncelleme Mevcut',
                message: `Yeni sürüm ${latest.version} yayınlandı!`,
                detail: `Şu anki sürüm: ${CONFIG.VERSION}\nYenilikler: ${latest.changelog || 'İyileştirmeler ve hata düzeltmeleri.'}`,
                buttons: ['İndir', 'Daha Sonra'],
                defaultId: 0,
                cancelId: 1
            });
            if (result.response === 0 && latest.downloadUrl) {
                const { shell } = require('electron');
                shell.openExternal(latest.downloadUrl);
            }
        }
    } catch (error) {
        console.error('Güncelleme kontrolü başarısız:', error.message);
        // FIX: Kullanıcıya hata bildir
        dialog.showErrorBox('Güncelleme Hatası', 'Güncelleme kontrolü yapılamadı. İnternet bağlantınızı kontrol edin.');
    }
}

function getProxyStatus() {
    return { active: activeProxy !== null, proxyUrl: activeProxy };
}

let offlineMode = false;
function setOfflineMode(mode) {
    offlineMode = mode;
    return offlineMode;
}
function isOffline() {
    return offlineMode;
}

function getApiKeys() {
    return {
        ipinfo: CONFIG.API_KEYS.IPINFO,
        leakcheck: CONFIG.API_KEYS.LEAKCHECK
    };
}
function setApiKey(service, key) {
    const envPath = path.join(__dirname, '.env');
    let envContent = '';
    try {
        if (fs.existsSync(envPath)) envContent = fs.readFileSync(envPath, 'utf8');
    } catch(e) {}
    if (service === 'ipinfo') {
        CONFIG.API_KEYS.IPINFO = key;
        const regex = /^IPINFO_TOKEN=.*$/m;
        if (regex.test(envContent)) envContent = envContent.replace(regex, `IPINFO_TOKEN=${key}`);
        else envContent += `\nIPINFO_TOKEN=${key}`;
    } else if (service === 'leakcheck') {
        CONFIG.API_KEYS.LEAKCHECK = key;
        const regex = /^LEAKCHECK_API_KEY=.*$/m;
        if (regex.test(envContent)) envContent = envContent.replace(regex, `LEAKCHECK_API_KEY=${key}`);
        else envContent += `\nLEAKCHECK_API_KEY=${key}`;
    }
    try { fs.writeFileSync(envPath, envContent.trim()); } catch(e) {}
    return { success: true };
}

const logPath = path.join(app.getPath('userData'), 'error.log');
function logError(error, context = '') {
    const logEntry = `[${new Date().toISOString()}] ${context}: ${error.stack || error.message || error}\n`;
    fs.appendFileSync(logPath, logEntry);
    console.error(logEntry);
}
process.on('uncaughtException', (err) => logError(err, 'uncaughtException'));
process.on('unhandledRejection', (reason) => logError(reason, 'unhandledRejection'));

async function webSearch(query) {
    const searchEngines = [
        { name: 'Google', url: `https://www.google.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Bing', url: `https://www.bing.com/search?q=${encodeURIComponent(query)}` }
    ];
    const results = [];
    for (const engine of searchEngines) {
        try {
            const response = await proxyGet(engine.url, { timeout: 10000 });
            const links = response.data.match(/https?:\/\/[^\s"']+/g) || [];
            const uniqueLinks = [...new Set(links.slice(0, 10))];
            results.push({ engine: engine.name, links: uniqueLinks });
        } catch(e) {
            results.push({ engine: engine.name, error: e.message });
        }
    }
    return results;
}

// ============ IPC HANDLER'LAR ============
ipcMain.handle('check-username', async (e, u) => { if (!checkRateLimit('username')) return { error: 'Rate limit: Çok hızlı istek gönderiyorsunuz.' }; return checkUsername(sanitizeInput(u)); });
ipcMain.handle('check-email', async (e, m) => { if (!checkRateLimit('email')) return { error: 'Rate limit.' }; return checkEmail(sanitizeInput(m)); });
ipcMain.handle('check-phone', async (e, p) => { if (!checkRateLimit('phone')) return { error: 'Rate limit.' }; return checkPhone(sanitizeInput(p)); });
ipcMain.handle('check-domain', async (e, d) => { if (!checkRateLimit('domain')) return { error: 'Rate limit.' }; return checkDomain(sanitizeInput(d)); });
ipcMain.handle('check-wayback', async (e, d) => { if (!checkRateLimit('wayback')) return { error: 'Rate limit.' }; return checkWayback(sanitizeInput(d)); });
ipcMain.handle('get-my-ip', async () => getMyIP());
ipcMain.handle('get-ip-location', async (e, ip) => { if (!checkRateLimit('ip')) return { success: false, error: 'Rate limit.' }; return getIPLocation(sanitizeInput(ip)); });
ipcMain.handle('get-detailed-ip-location', async (e, ip) => { if (!checkRateLimit('ip')) return { success: false, error: 'Rate limit.' }; return getDetailedIPLocation(sanitizeInput(ip)); });
ipcMain.handle('get-dns-history', async (e, d) => { if (!checkRateLimit('dns')) return { success: false, error: 'Rate limit.' }; return getDNSHistory(sanitizeInput(d)); });
ipcMain.handle('scan-ports', async (e, ip) => { if (!checkRateLimit('port', 3, 15000)) return { openPorts: [], totalOpen: 0, error: 'Rate limit: Port tarama çok sık yapılamaz.' }; return scanPorts(sanitizeInput(ip)); });
ipcMain.handle('get-ip-from-domain', async (e, d) => { if (!checkRateLimit('domain')) return { success: false, error: 'Rate limit.' }; return getIPFromDomain(sanitizeInput(d)); });
ipcMain.handle('generate-fake-user', async () => generateFakeUser());
ipcMain.handle('save-report', async (e, d, f) => saveReport(d, sanitizeInput(f)));
ipcMain.handle('calculate-score', async (e, r) => calculateScore(r));
ipcMain.handle('get-crt-subdomains', async (e, d) => { if (!checkRateLimit('crt', 3, 15000)) return { subdomains: [], total: 0, error: 'Rate limit.' }; return getCRTSubdomains(sanitizeInput(d)); });
ipcMain.handle('get-history', async () => history);
ipcMain.handle('clear-history', async () => { history = []; await saveHistoryToDisk(); return true; });
ipcMain.handle('add-to-history', async (e, entry) => { addToHistoryInternal(entry); return true; });
ipcMain.handle('add-to-correlation', async (e, t, v, s) => { correlationEngine.addData(t, sanitizeInput(v), s); return correlationEngine.getOverallRisk(); });
ipcMain.handle('get-correlation-report', async () => correlationEngine.generateReport());
ipcMain.handle('set-proxy', async (e, url) => setProxy(url));
ipcMain.handle('get-proxy', async () => ({ proxy: activeProxy }));
ipcMain.handle('clear-proxy', async () => clearProxy());
ipcMain.handle('batch-username', async (e, u) => { if (!checkRateLimit('batch', 2, 30000)) return []; return batchUsernameSearch(u); });
ipcMain.handle('batch-domain', async (e, d) => { if (!checkRateLimit('batch', 2, 30000)) return []; return batchDomainSearch(d); });
ipcMain.handle('get-graph-data', async () => getGraphData());
ipcMain.handle('get-risk-dashboard', async () => getRiskDashboard());
ipcMain.handle('analyze-metadata', async (e, p) => analyzeImageMetadataFromPath(p));
ipcMain.handle('analyze-metadata-buffer', async (e, buffer) => analyzeImageMetadataFromBuffer(Buffer.from(buffer)));
ipcMain.handle('generate-pdf-report', async (e, d, n) => { if (!checkRateLimit('pdf', 3, 30000)) return { success: false, error: 'Rate limit.' }; return generatePDFReport(d, n); });
ipcMain.handle('save-forensic-report', async (e, d, cn) => { if (!checkRateLimit('forensic', 3, 30000)) return { success: false, error: 'Rate limit.' }; return saveForensicReport(d, cn); });
ipcMain.handle('check-typosquatting', async (e, d) => { if (!checkRateLimit('typo', 3, 20000)) return { typosquattingDomains: [], totalActive: 0, error: 'Rate limit.' }; return checkTyposquatting(d); });
ipcMain.handle('check-employee-leaks', async (e, d) => { if (!checkRateLimit('leak', 3, 20000)) return { leakedEmails: [], totalLeaked: 0, error: 'Rate limit.' }; return checkEmployeeLeaks(d); });
ipcMain.handle('vip-protection-scan', async (e, n, em) => { if (!checkRateLimit('vip', 3, 20000)) return { findings: [], riskScore: 0, error: 'Rate limit.' }; return vipProtectionScan(n, em); });
ipcMain.handle('get-eula', async () => getEULA());
ipcMain.handle('set-batch-concurrency', async (e, newConcurrency) => setBatchConcurrency(newConcurrency));
ipcMain.handle('generate-html-report', async (e, data) => generateHTMLReport(data));

ipcMain.handle('get-proxy-status', async () => getProxyStatus());
ipcMain.handle('set-offline-mode', async (e, mode) => setOfflineMode(mode));
ipcMain.handle('is-offline', async () => isOffline());
ipcMain.handle('get-api-keys', async () => getApiKeys());
ipcMain.handle('set-api-key', async (e, service, key) => setApiKey(service, key));
ipcMain.handle('get-error-log', async () => {
    try { if (fs.existsSync(logPath)) return fs.readFileSync(logPath, 'utf8'); } catch(e) {}
    return '';
});
ipcMain.handle('clear-error-log', async () => { try { fs.unlinkSync(logPath); } catch(e) {} return true; });
ipcMain.handle('web-search', async (e, query) => webSearch(query));
ipcMain.handle('check-updates', async () => checkForUpdates());

// ============ WINDOW ============
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1600, height: 1000,
        webPreferences: { nodeIntegration: false, contextIsolation: true, preload: path.join(__dirname, 'preload.js') }
    });
    mainWindow.loadFile('index.html');
    createTray();
    setTimeout(() => checkForUpdates(), 5000);
}

app.whenReady().then(() => {
    loadHistoryFromDisk();
    createWindow();
}).catch(e => {
    console.error('Uygulama başlatılamadı:', e);
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
