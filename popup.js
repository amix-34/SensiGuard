// SensiGuard - popup.js
// Renders 4 states (ready / high risk / caution / no danger / off), tabs, and ⓘ tips.
//
// SECURITY NOTES
//  • No innerHTML anywhere: all text goes in with textContent, icons are
//    cloned from <template> elements in popup.html.
//  • Scan results are read from chrome.storage.session (memory only, never
//    written to disk, not readable by content scripts).
//  • The masked sample (e.g. ******-**-5678) is never stored: it is asked
//    for live from the page's own content script when the popup opens.
//  • Every incoming message is checked: same extension id + same tab.

'use strict';

const $ = (id) => document.getElementById(id);

const TIPS = {
    ic: {
        title:   '🪪 Why the IC number?',
        text:    'Your MyKad number never changes. Criminals can use it to open accounts or take loans in your name. A password can be reset, but an IC number cannot.',
        detects: 'Detects: 12 digits, e.g. 990101-14-5678'
    },
    card: {
        title:   '💳 Why the credit card number?',
        text:    'Your card number gives direct access to your money. If a criminal gets it, they can try to spend your money straight away. Hiding it on screen helps stop people nearby from reading it.',
        detects: 'Detects: Visa, Mastercard and Amex, e.g. 4111 1111 1111 1111'
    },
    phone: {
        title:   '📱 Why the phone number?',
        text:    'Scammers use your phone number for fake calls and phishing messages. Banks and apps also send verification codes (OTP) to it. With your IC too, it is easier to pretend to be you.',
        detects: 'Detects: Malaysian mobile numbers, e.g. 012-3456789'
    }
};

const MASK_TITLES = { ic: 'IC number masked', card: 'Credit card masked', phone: 'Phone number masked' };
const STATUSES    = ['high', 'caution', 'weak', 'strong'];

let state = {
    isOn: true,
    autoMask: true,
    scan: null,    // { status, reasons, info, checks }
    masked: null,  // { type, sample } — live from the page, never stored
    scanMs: null
};
let openTip = null;
let tabId   = null;

// ── Safe DOM helpers (replace innerHTML) ────────────────────────
// rich(el, ['plain text', {b: 'bold text'}, {br: true}, ...])
function rich(el, parts) {
    el.replaceChildren(...parts.map(p => {
        if (typeof p === 'string') return document.createTextNode(p);
        if (p.br) return document.createElement('br');
        const b = document.createElement('b');
        b.textContent = String(p.b);
        return b;
    }));
}

function icon(name) {
    return $('ico-' + name).content.cloneNode(true);
}

// Bold the "N info note(s)" phrase inside a plain sentence
function boldInfo(text) {
    const m = String(text).match(/^(.*?)(\d+ info notes?)(.*)$/);
    return m ? [m[1], { b: m[2] }, m[3]] : [String(text)];
}

const str  = (v, max = 300) => String(v == null ? '' : v).slice(0, max);
const strs = (a) => Array.isArray(a) ? a.slice(0, 10).map(x => str(x)) : [];

// Accept only well-formed results (protects the popup from bad data)
function cleanScan(scan) {
    if (!scan || !STATUSES.includes(scan.status)) return null;
    return { status: scan.status, reasons: strs(scan.reasons), info: strs(scan.info),
             checks: (scan.checks && typeof scan.checks === 'object') ? scan.checks : null };
}

function cleanMasked(m) {
    if (!m || !MASK_TITLES[m.type]) return null;
    const sample = str(m.sample, 40);
    return /^[\d*\s-]+$/.test(sample) ? { type: m.type, sample } : null;   // only * digits spaces hyphens
}

// ── Load state for the current tab ──────────────────────────────
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    tabId = tabs[0] ? tabs[0].id : null;
    chrome.storage.local.get(['isOn', 'autoMask'], (settings) => {
        state.isOn     = settings.isOn !== false;
        state.autoMask = settings.autoMask !== false;
        $('maskToggle').checked = state.autoMask;
        chrome.storage.session.get('tabResults', (data) => {
            applyResult(((data && data.tabResults) || {})[tabId]);
            askPageForMasked();
        });
    });
});

function applyResult(r) {
    r = r || {};
    state.scan   = cleanScan(r.scan);
    state.scanMs = /^\d+(\.\d+)?$/.test(str(r.scanMs)) ? str(r.scanMs, 12) : null;
    render();
}

// The masked sample lives only inside the page's content script
function askPageForMasked() {
    if (tabId == null) return;
    chrome.tabs.sendMessage(tabId, { action: 'getMasked' }, { frameId: 0 }, (res) => {
        if (chrome.runtime.lastError) return;          // no content script (e.g. chrome:// page)
        state.masked = cleanMasked(res);
        render();
    });
}

// Live updates while the popup is open
chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'session' || !changes.tabResults) return;
    applyResult((changes.tabResults.newValue || {})[tabId]);
});

chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id) return;                     // only our own extension
    if (!sender.tab || sender.tab.id !== tabId) return;              // only the tab this popup shows
    if (typeof sender.url !== 'string' || !/^https?:\/\//.test(sender.url)) return;   // only a content script
    if (msg && msg.action === 'maskedUpdate') {
        state.masked = cleanMasked(msg);
        render();
    }
});

// ── Render ──────────────────────────────────────────────────────
function render() {
    let theme, badge, ico, title, desc, footer;

    if (!state.isOn) {
        theme  = 'grey';
        badge  = 'Off';
        ico    = 'shield';
        title  = 'Protection off';
        desc   = ['Nothing is scanned or masked. Turn the switch on to start SensiGuard.'];
        footer = ['🔒 All scanning happens on your device.'];
    } else if (state.scan && state.scan.status === 'high') {
        theme  = 'red';
        badge  = 'High risk';
        ico    = 'alert';
        title  = 'High risk site';
        desc   = [{ b: 'Why:' }, ' ' + (state.scan.reasons.join('; ') || 'this site does not use HTTPS') + '.', { br: true },
                  { b: 'Advice:' }, ' do not enter IC or credit card details here.'];
        footer = ['Masking hides data on screen only. This is a warning, not proof.'];
    } else if (state.scan && (state.scan.status === 'caution' || state.scan.status === 'weak')) {
        theme  = 'orange';
        badge  = 'Caution';
        ico    = 'warn';
        title  = 'Use caution';
        const why   = state.scan.reasons.join('; ') || 'weak protection signs were found';
        const extra = /protection/.test(why) ? '' : ' This site has weaker protection.';
        desc   = [{ b: 'Why:' }, ' ' + why + '.' + extra, { br: true },
                  { b: 'Advice:' }, ' check the website address carefully before entering personal data.'];
        footer = ['Masking hides data on screen only. This is a warning, not proof.'];
    } else if (state.scan && state.scan.status === 'strong') {
        theme  = 'green';
        badge  = 'Monitoring';
        ico    = 'check';
        title  = 'No danger found';
        const n = state.scan.info.length;
        const c = state.scan.checks || {};
        const notes = n + ' info note' + (n > 1 ? 's' : '');
        const first = c.goodText ? str(c.goodText)
            : (c.headerWeak ? `HTTPS is fine. ${notes} below about weaker security headers.`
                            : 'HTTPS and security headers look fine.' + (n ? ` ${notes} below.` : ''));
        desc   = [...boldInfo(first), { br: true }, { b: 'Stay careful:' }, ' this does not guarantee the site is safe.'];
        footer = ['Masking hides data on screen only.', { br: true }, '🔒 All scanning happens on your device.'];
    } else {
        theme  = 'blue';
        badge  = 'Ready';
        ico    = 'shield';
        title  = 'Ready to scan';
        desc   = ['Protection is on. SensiGuard is checking this website.'];
        footer = ['🔒 All scanning happens on your device. Typed data is never sent or stored.'];
    }

    $('head').className        = 'head theme-' + theme;
    $('badge').textContent     = badge;
    $('heroIcon').replaceChildren(icon(ico));
    $('heroTitle').textContent = title;
    rich($('heroDesc'), desc);
    if ($('panel-why').hidden) rich($('footer'), footer);

    // Power switch
    const btn = $('powerBtn');
    btn.classList.toggle('off', !state.isOn);
    btn.setAttribute('aria-checked', String(state.isOn));
    $('powerLabel').textContent = state.isOn ? 'ON' : 'OFF';

    // Masked notice — only after the user typed something sensitive
    const box = $('maskedBox');
    if (state.isOn && state.masked) {
        box.hidden = false;
        box.className = 'masked t-' + theme;
        $('maskedTitle').textContent  = MASK_TITLES[state.masked.type];
        $('maskedSample').textContent = 'Shown on screen as ' + state.masked.sample;
    } else {
        box.hidden = true;
    }

    $('scanTime').textContent = state.scanMs ? state.scanMs + ' ms' : '—';
    renderChecks();
    renderTip();
}

function renderTip() {
    document.querySelectorAll('.chip').forEach(c => c.classList.toggle('active', c.dataset.key === openTip));
    $('monLabel').textContent = openTip
        ? 'Currently monitoring · tap ⓘ again to close'
        : 'Currently monitoring · tap ⓘ to learn why';

    if (!openTip || !TIPS[openTip]) { $('tip').hidden = true; return; }
    const t = TIPS[openTip];
    $('tipTitle').textContent   = t.title;
    $('tipText').textContent    = t.text;
    $('tipDetects').textContent = t.detects;
    $('tip').hidden = false;
}

// ── Events ──────────────────────────────────────────────────────
$('powerBtn').addEventListener('click', () => {
    state.isOn = !state.isOn;
    chrome.storage.local.set({ isOn: state.isOn });     // content scripts react via storage.onChanged
    if (!state.isOn) {
        chrome.runtime.sendMessage({ action: 'protectionOff' }).catch(() => {});
        state.scan = null; state.masked = null;
    }
    render();
});

$('maskToggle').addEventListener('change', (e) => {
    state.autoMask = e.target.checked;
    chrome.storage.local.set({ autoMask: state.autoMask });
});

document.querySelectorAll('.info').forEach(btn => {
    btn.addEventListener('click', () => {
        openTip = (openTip === btn.dataset.key) ? null : btn.dataset.key;
        renderTip();
    });
});

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === tab));
        $('panel-protect').hidden = tab.dataset.tab !== 'protect';
        $('panel-why').hidden     = tab.dataset.tab !== 'why';
        if (tab.dataset.tab === 'why') {
            $('footer').textContent = 'Examples are fake. SensiGuard never saves what you type.';
        } else {
            render();
        }
    });
});

// ── Security checks list ────────────────────────────────────────
function row(cls, mark, title, note) {
    const wrap = document.createElement('div');
    wrap.className = 'check ' + cls;
    const ic = document.createElement('span');
    ic.className = 'ic';
    ic.textContent = mark;
    const body = document.createElement('div');
    const b = document.createElement('b');
    b.textContent = str(title);
    body.append(b);
    if (note) {
        const small = document.createElement('small');
        small.textContent = str(note);
        body.append(document.createElement('br'), small);
    }
    wrap.append(ic, body);
    return wrap;
}

function renderChecks() {
    if (!state.isOn) { $('checksBox').hidden = true; return; }
    $('checksBox').hidden = false;

    const c = state.scan && state.scan.checks;

    // READY: no result yet → every check shows "…"
    if (!c) {
        $('checksList').replaceChildren(
            row('wait', '…', 'HTTPS connection', 'Checking...'),
            row('wait', '…', 'CSP header'),
            row('wait', '…', 'HSTS header'),
            row('wait', '…', 'Software versions'),
            row('wait', '…', 'Signs of weak XSS / SQL injection protection')
        );
        return;
    }

    // Header states: 'pass' | 'weak' | 'missing' | null  (true/false = older results)
    // level decides the icon: 'info' = blue i (one header missing / weak), 'caution' = orange !
    const header = (v, name, note, level) => {
        if (v === 'pass' || v === true)     return row('ok',   '✓', name + ' header found',   note);
        if (v === 'weak')                   return row('note', 'i', name + ' header weak',    note);
        if (v === 'missing' || v === false) return level === 'info'
                                                ? row('note', 'i', name + ' header missing', note)
                                                : row('warn', '!', name + ' header missing', note);
        return row('na', '…', name + ' header', 'Could not be read (reload the page)');
    };

    const outdated  = strs(c.outdated);
    const libsFound = strs(c.libsFound);

    $('checksList').replaceChildren(
        c.https ? row('ok',   '✓', 'HTTPS connection', 'Chrome also blocks most bad certificates')
                : row('high', '✕', 'No HTTPS connection', 'Page loads over http://'),
        header(c.csp,  'CSP',  c.cspNote,  c.cspLevel),
        header(c.hsts, 'HSTS', c.hstsNote, c.hstsLevel),
        outdated.length
            ? row('note', 'i', 'Outdated software: ' + outdated.join(', '),
                  state.scan.status === 'strong' ? 'Info only. Many trusted sites still use older versions.' : 'Info only')
            : row('ok', '✓', 'No outdated software found',
                  libsFound.length ? 'Checked: ' + libsFound.join(', ') : 'Checked: jQuery, Bootstrap, AngularJS, Lodash'),
        c.weakSigns
            ? row('warn', '!', 'Signs of weak XSS / SQL injection protection', 'Warning sign check only, not a test')
            : row('ok',   '✓', 'No signs of weak XSS / SQL injection protection', 'Warning sign check only, not a test')
    );
}

// Show the running version next to the name
try {
    const v = document.createElement('span');
    v.className = 'ver';
    v.textContent = ' v' + chrome.runtime.getManifest().version;
    document.querySelector('.brand').appendChild(v);
} catch (e) {}
