// SensiGuard - background.js
// content.js checks each page by itself (including late-loading forms).
// This file reads the CSP / HSTS headers and keeps each tab's result so
// the popup can display it.
//
// SECURITY NOTES
//  • Everything is kept in chrome.storage.session: memory only, never
//    written to disk, cleared when the browser closes, and not readable
//    by content scripts (default TRUSTED_CONTEXTS access level).
//  • No typed data is ever stored. Masked samples are only passed from an
//    iframe to its own top page, never saved.
//  • Every message is checked: it must come from this extension, and
//    page-related messages must come from a content script in a tab.

'use strict';

const STATUSES    = ['high', 'caution', 'strong'];
const FIELD_TYPES = ['ic', 'card', 'phone', 'pin', 'login'];
const MASK_TYPES  = ['ic', 'card', 'phone'];

const store = chrome.storage.session;

async function saveTabResult(tabId, patch) {
    const d = await store.get('tabResults');
    const all = d.tabResults || {};
    all[tabId] = Object.assign({}, all[tabId] || {}, patch);
    await store.set({ tabResults: all });
}

async function clearTab(tabId) {
    const d = await store.get(['tabResults', 'tabHeaders']);
    const results = d.tabResults || {}, headers = d.tabHeaders || {};
    delete results[tabId];
    delete headers[tabId];
    await store.set({ tabResults: results, tabHeaders: headers });
}

// ── Small validators (never trust message contents) ─────────────
const str  = (v, max = 300) => String(v == null ? '' : v).slice(0, max);
const strs = (a, max = 10) => Array.isArray(a) ? a.slice(0, max).map(x => str(x)) : [];
const pick = (a, allowed) => Array.isArray(a) ? [...new Set(a.filter(x => allowed.includes(x)))] : [];
const tri  = (v) => ['pass', 'weak', 'missing'].includes(v) ? v : null;
const lvl  = (v) => ['ok', 'info', 'caution'].includes(v) ? v : null;

function cleanChecks(c) {
    if (!c || typeof c !== 'object') return null;
    return {
        https: c.https === true,
        csp:  tri(c.csp),  cspNote:  str(c.cspNote, 120),  cspLevel:  lvl(c.cspLevel),
        hsts: tri(c.hsts), hstsNote: str(c.hstsNote, 120), hstsLevel: lvl(c.hstsLevel),
        outdated:   strs(c.outdated, 4),
        libsFound:  strs(c.libsFound, 4),
        weakSigns:  c.weakSigns === true,
        headerWeak: Math.max(0, Math.min(2, Number(c.headerWeak) || 0)),
        infoCount:  Math.max(0, Math.min(10, Number(c.infoCount) || 0)),
        goodText:   str(c.goodText, 160)
    };
}

// ── Read security headers of every page (needs webRequest + host permissions)
// We only READ three headers. Nothing is blocked or changed, and the page
// URL is not kept.
chrome.webRequest.onHeadersReceived.addListener((details) => {
    if (details.tabId < 0) return;
    const get = (name) => {
        const h = (details.responseHeaders || []).find(x => x.name.toLowerCase() === name);
        return h ? str(h.value, 2000) : null;
    };
    const cspValue  = get('content-security-policy');
    const hstsValue = get('strict-transport-security');
    const info = {
        csp:           cspValue !== null,
        cspValue:      cspValue || '',
        cspReportOnly: get('content-security-policy-report-only') !== null,
        hsts:          hstsValue !== null,
        hstsValue:     hstsValue || ''
    };
    store.get('tabHeaders', (d) => {
        const all = d.tabHeaders || {};
        all[details.tabId] = info;
        store.set({ tabHeaders: all });
    });
}, { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] }, ['responseHeaders']);

// ── Messages ────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;            // only our own extension
    if (!msg || typeof msg.action !== 'string') return;

    // sender.url is set by Chrome and cannot be faked by a web page.
    const url       = typeof sender.url === 'string' ? sender.url : '';
    const fromPopup = url.startsWith(chrome.runtime.getURL('popup.html'));
    const fromPage  = /^https?:\/\//.test(url) && !!sender.tab;       // a content script in a web page
    const tabId     = fromPage && Number.isInteger(sender.tab.id) ? sender.tab.id : null;

    // ── From the popup ──
    if (msg.action === 'protectionOff' && fromPopup) {
        store.set({ tabResults: {} });
        return;
    }

    // ── From a content script (must be inside a web page tab) ──
    if (tabId === null) return;

    // content.js asks for this page's headers (top frame only)
    if (msg.action === 'getHeaders' && sender.frameId === 0) {
        store.get('tabHeaders', (d) => sendResponse((d.tabHeaders || {})[tabId] || null));
        return true; // answer arrives asynchronously
    }

    // A page found a sensitive field and checked its security
    if (msg.action === 'scanResult' && sender.frameId === 0 && STATUSES.includes(msg.status)) {
        saveTabResult(tabId, {
            scan:   { status: msg.status, reasons: strs(msg.reasons, 5), info: strs(msg.info, 5), checks: cleanChecks(msg.checks) },
            fields: pick(msg.fields, FIELD_TYPES),
            scanMs: /^\d+(\.\d+)?$/.test(str(msg.scanMs)) ? str(msg.scanMs, 12) : null
        });
        return;
    }

    // An iframe found fields → pass the field TYPES to the top page of the same tab
    if (msg.action === 'frameFields' && sender.frameId !== 0) {
        const fields = pick(msg.fields, FIELD_TYPES);
        if (fields.length) chrome.tabs.sendMessage(tabId, { action: 'frameFields', fields }, { frameId: 0 }).catch(() => {});
        return;
    }

    // An iframe masked a value → tell its top page (so the popup can ask it later).
    // Passed on in memory only; never stored.
    if (msg.action === 'maskedUpdate' && sender.frameId !== 0 && MASK_TYPES.includes(msg.type)) {
        const sample = str(msg.sample, 40);
        if (/^[\d*\s-]+$/.test(sample)) {
            chrome.tabs.sendMessage(tabId, { action: 'maskedFromFrame', type: msg.type, sample }, { frameId: 0 }).catch(() => {});
        }
        return;
    }
});

// New page load in a tab → forget the old result
chrome.tabs.onUpdated.addListener((tabId, info) => {
    if (info.status === 'loading') {
        store.get('tabResults', (d) => {
            const all = d.tabResults || {};
            if (all[tabId]) { delete all[tabId]; store.set({ tabResults: all }); }
        });
    }
});

chrome.tabs.onRemoved.addListener((tabId) => clearTab(tabId));

// One-time cleanup: older versions kept results in storage.local (on disk)
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.remove('tabResults');
});
