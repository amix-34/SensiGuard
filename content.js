// SensiGuard - content.js
//
// SECURITY NOTES
//  • Typed values are never changed, stored or logged. Only a masked
//    sample (e.g. ******-**-5678) is kept in this script's memory so the
//    popup can show it; it is never written to any storage.
//  • No innerHTML: the on-page banner is built with DOM nodes + textContent.
//  • Messages are accepted only from this extension's own background /
//    popup (sender.id check, and never from another content script).
//  • Library versions reported by the page are validated before use.
'use strict';
console.info('[SensiGuard] v2.3 loaded. Masking only hides digits on screen; typed values are never changed.');

let autoMask    = true;
let isWatching  = false;
let maskedCount = 0;
let bannerEl    = null;
let lastMasked  = null;    // { type, sample } — memory only, for the popup
const IS_TOP     = window.top === window;

const piiPatterns = {
    malaysianIC: /\b(\d{6})-?(\d{2})-?(\d{4})\b/g,
    creditCard:  /\b(\d{4})[ -]?(\d{4})[ -]?(\d{4})[ -]?(\d{4})\b/g,
    mobilePhone: /\b(01[0-9])-?(\d{3,4})(\d{4})\b/g
};

// ── Trusted domains ──────────────────────────────────────────────
const trustedDomains = [
    'maybank2u.com.my','maybank.com.my','cimbclicks.com.my','cimb.com.my',
    'hlonline.com.my','hongleong.com.my','publicbankberhad.com.my','pbebank.com',
    'rhbgroup.com','rhbbank.com.my','ambankgroup.com','ambank.com.my',
    'bankislam.com.my','muamalat.com.my','affin.com.my','affinbank.com.my',
    'alliancebank.com.my','bsn.com.my','bankrakyat.com.my','agro.com.my','bnm.gov.my',
    'gov.my','edu.my','padu.gov.my','lhdn.gov.my','hasil.gov.my',
    'jpj.gov.my','kwsp.gov.my','epf.gov.my','perkeso.gov.my','socso.com.my',
    'mysikap.gov.my','myeg.com.my',
    'shopee.com.my','shopee.com','lazada.com.my','lazada.com','zalora.com.my',
    'mudah.my','lelong.com.my','grabpay.com','grab.com','boost.com.my',
    'touchngo.com.my','tngdigital.com.my','bigpay.com','senangpay.com',
    'ipay88.com','molpay.com','razer.com',
    'amazon.com','amazon.co.uk','ebay.com','aliexpress.com','alibaba.com','etsy.com',
    'paypal.com','stripe.com','wise.com','revolut.com',
    'hsbc.com.my','hsbc.com','sc.com','standardchartered.com',
    'ocbc.com.my','ocbc.com','uob.com.my','uob.com',
    'citibank.com.my','citibank.com','visa.com','mastercard.com',
    'google.com','facebook.com','instagram.com','twitter.com','x.com',
    'linkedin.com','microsoft.com','live.com','outlook.com',
    'apple.com','github.com','netflix.com','spotify.com',
];

// ── Security check ───────────────────────────────────────────────
// Checks, and what each one really means:
//  1. HTTPS            – page uses https:// (Chrome itself already blocks
//                        most pages with a bad certificate, so this also
//                        covers the certificate check)
//  2. Outdated software – built-in version rules (see OUTDATED_RULES)
//  3. Signs of weak protection against XSS / SQL injection – NOT a test.
//                        We only look for warning signs: no CSP header,
//                        CSP that allows 'unsafe-inline', or a form that
//                        sends data over plain http://
//  4. Headers           – CSP and HSTS, read by background.js
//  + Hostname signs     – IP address, phishing words, risky domain endings

// Built-in rules: "older than X is outdated" (each has a public CVE / end-of-life)
const OUTDATED_RULES = [
    { name: 'jQuery',    isOld: v => cmp(v, '3.5.0') < 0,                      why: 'older than 3.5.0 (XSS, CVE-2020-11022)' },
    { name: 'Bootstrap', isOld: v => cmp(v, '3.4.1') < 0 || (major(v) === 4 && cmp(v, '4.3.1') < 0),
                                                                               why: 'older than 3.4.1 / 4.3.1 (XSS, CVE-2019-8331)' },
    { name: 'AngularJS', isOld: v => major(v) === 1,                           why: 'version 1.x, no security updates since Dec 2021' },
    { name: 'Lodash',    isOld: v => cmp(v, '4.17.21') < 0,                    why: 'older than 4.17.21 (CVE-2021-23337)' }
];

function major(v) { return parseInt(String(v).split('.')[0], 10) || 0; }
function cmp(a, b) {                       // compare "1.12.4" with "3.5.0"
    const x = String(a).split('.').map(n => parseInt(n, 10) || 0);
    const y = String(b).split('.').map(n => parseInt(n, 10) || 0);
    for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); }
    return 0;
}

// Find library versions: ask detect-libs.js (page world), then also look
// at <script src="jquery-1.12.4.min.js"> file names as a backup
function findLibraries() {
    const libs = {};
    try {
        document.dispatchEvent(new CustomEvent('sensiguard-request-libs'));
        // The page can write to this attribute, so accept only known names
        // and plain version numbers (e.g. "3.7.1")
        const known = ['jQuery', 'AngularJS', 'Bootstrap', 'Lodash'];
        const list  = JSON.parse(document.documentElement.getAttribute('data-sensiguard-libs') || '[]');
        if (Array.isArray(list)) list.slice(0, 8).forEach(l => {
            if (l && known.includes(l.name) && /^\d{1,3}(\.\d{1,4}){0,3}$/.test(String(l.version))) libs[l.name] = String(l.version);
        });
    } catch (e) {}
    const fromSrc = { jQuery: /jquery[.-]?v?(\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js/i,
                      Bootstrap: /bootstrap[.-]?v?(\d+\.\d+(?:\.\d+)?)(?:\.bundle)?(?:\.min)?\.js/i,
                      AngularJS: /angular(?:js)?[\/.-]v?(1\.\d+(?:\.\d+)?)(?:\/angular)?(?:\.min)?\.js/i,
                      Lodash: /lodash[.@\/-]v?(\d+\.\d+(?:\.\d+)?)/i };
    document.querySelectorAll('script[src]').forEach(sc => {
        for (const [name, re] of Object.entries(fromSrc)) {
            const m = sc.src.match(re);
            if (m && !libs[name]) libs[name] = m[1];
        }
    });
    return libs;
}

// ── CSP and HSTS rule ────────────────────────────────────────────
//            CSP                                         HSTS
//  pass      script-src 'self'                           max-age >= 1 year (31536000)
//  weak      script-src * or 'unsafe-inline' (no nonce/hash)   max-age < 1 year   → INFO ONLY, stays green
//  missing   no header, or Report-Only                    no header, or max-age=0 → CAUTION, orange
//  null      could not be read (e.g. page from cache)

const ONE_YEAR = 31536000;

function rateCSP(headers) {
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    const value = ((headers && headers.cspValue) || (meta && meta.content) || '').toLowerCase();
    if (!headers && !meta) return { state: null };
    if (!value.trim()) {
        return { state: 'missing',
                 note: headers && headers.cspReportOnly ? 'Report-Only mode: rules are not enforced' : 'No rule on where scripts can load from' };
    }
    // script-src, or default-src when script-src is not set
    const dir = (name) => { const m = value.match(new RegExp('(?:^|;)\\s*' + name + '\\s+([^;]*)')); return m ? m[1] : null; };
    const src = dir('script-src') ?? dir('default-src');
    if (src === null) return { state: 'weak', note: 'No script-src rule, so scripts are not limited. Info only.' };
    const hasNonceOrHash = /'nonce-|'sha(256|384|512)-/.test(src);
    if (/(^|\s)\*(\s|$)/.test(src))                         return { state: 'weak', note: 'Allows scripts from any site (*). Info only.' };
    if (src.includes("'unsafe-inline'") && !hasNonceOrHash) return { state: 'weak', note: "Allows 'unsafe-inline' scripts. Info only." };
    return { state: 'pass', note: 'Restricts where scripts can load from' };
}

function rateHSTS(headers, isHTTPS) {
    if (!isHTTPS) return { state: 'missing', note: 'Not used on http:// pages' };
    if (!headers) return { state: null };
    if (!headers.hsts) return { state: 'missing', note: 'Browser may not always force HTTPS' };
    const m = (headers.hstsValue || '').match(/max-age\s*=\s*"?(\d+)/i);
    const age = m ? parseInt(m[1], 10) : 0;
    if (age <= 0)        return { state: 'missing', note: 'max-age=0 turns HSTS off' };
    if (age < ONE_YEAR)  return { state: 'weak', note: 'max-age is ' + humanAge(age) + ' (less than 1 year). Info only.' };
    return { state: 'pass', note: 'max-age: ' + humanAge(age) };
}

function humanAge(sec) {
    const d = Math.round(sec / 86400);
    if (d >= 365) { const y = Math.round(d / 365); return y + ' year' + (y > 1 ? 's' : ''); }
    if (d >= 30)  { const mo = Math.round(d / 30); return mo + ' month' + (mo > 1 ? 's' : ''); }
    if (d >= 1)   return d + ' day' + (d > 1 ? 's' : '');
    return sec + ' seconds';
}

function checkPageSecurity(headers) {
    // FINAL RULE (if more than one applies, the highest level wins)
    //   No HTTPS / invalid certificate        → HIGH RISK  (red)
    //   CSP or HSTS missing                   → CAUTION    (orange)
    //   Signs of weak XSS / SQL protection    → CAUTION    (orange)
    //   CSP or HSTS weak                      → INFO ONLY  (stays green)
    //   Outdated library (e.g. old jQuery)    → INFO ONLY  (stays green)
    //   All checks pass                       → NO DANGER  (green)
    const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
    const isHTTPS  = window.location.protocol === 'https:';
    const high = [], caution = [], info = [];

    // 1. HTTPS / certificate (Chrome already blocks most invalid certificates)
    if (!isHTTPS) high.push('this site does not use HTTPS. Anything you type can be read by others on the network');

    // 2. Headers
    const csp  = rateCSP(headers);
    const hsts = rateHSTS(headers, isHTTPS);
    // v7 rule:  BOTH missing → caution (orange)
    //           only ONE missing → info only (stays green)
    const cspMissing  = csp.state === 'missing';
    const hstsMissing = hsts.state === 'missing';
    const bothMissing = cspMissing && hstsMissing;
    let cspLevel  = csp.state  === 'pass' ? 'ok' : csp.state  === 'weak' ? 'info' : null;
    let hstsLevel = hsts.state === 'pass' ? 'ok' : hsts.state === 'weak' ? 'info' : null;

    if (bothMissing) {
        cspLevel = hstsLevel = 'caution';
        if (isHTTPS) caution.push('no CSP header and no HSTS header. This site has neither protection');
        else csp.note = '';                                   // red screen already explains http://
    } else if (cspMissing) {
        cspLevel = 'info';
        csp.note = 'Info only. Many trusted sites do not use CSP.';
        info.push('CSP header missing');
    } else if (hstsMissing) {
        hstsLevel = 'info';
        hsts.note = hsts.note === 'max-age=0 turns HSTS off'
            ? 'max-age=0 turns HSTS off. Info only.'
            : 'Info only. HTTPS is still used on this page.';
        info.push('HSTS header missing');
    }
    if (csp.state === 'weak')  info.push('CSP header weak');
    if (hsts.state === 'weak') info.push('HSTS header weak');

    // 3. Signs of weak XSS / SQL injection protection (a warning sign, not a test)
    const insecureForm = [...document.forms].some(f => (f.getAttribute('action') || '').toLowerCase().startsWith('http:'));
    if (insecureForm) caution.push('a form sends data without HTTPS');

    // 4. Outdated software → info only
    const libs = findLibraries();
    const outdated = [];
    OUTDATED_RULES.forEach(r => {
        if (libs[r.name] && r.isOld(libs[r.name])) outdated.push(r.name + ' ' + libs[r.name]);
    });
    if (outdated.length) info.push('outdated software: ' + outdated.join(', '));

    const level  = high.length ? 'high' : caution.length ? 'caution' : 'safe';
    const status = level === 'safe' ? 'strong' : level;     // 'strong' kept for older code

    const checks = {
        https: isHTTPS,
        csp:  csp.state,  cspNote:  csp.note  || '', cspLevel,
        hsts: hsts.state, hstsNote: hsts.note || '', hstsLevel,
        outdated,
        libsFound: Object.entries(libs).map(([n, v]) => n + ' ' + v),
        weakSigns: insecureForm,
        headerWeak: (csp.state === 'weak') + (hsts.state === 'weak'),
        infoCount: info.length
    };
    const isTrusted = trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d));
    return { status, level, isSecure: level === 'safe', reasons: level === 'high' ? high : caution, info, checks, trusted: isTrusted };
}

// Text for the green result, based on what was really found
function strongText(checks) {
    const n = checks.infoCount;
    const notes = n + ' info note' + (n > 1 ? 's' : '');
    const below = n ? ' ' + notes + ' below.' : '';
    if (checks.csp === null || checks.hsts === null) return 'HTTPS is on and no warning signs were found.' + below;
    if (checks.csp === 'missing'  && checks.hsts === 'pass') return 'HTTPS and HSTS look fine.' + below;
    if (checks.hsts === 'missing' && checks.csp  === 'pass') return 'HTTPS and CSP look fine.' + below;
    if (checks.headerWeak || checks.csp === 'missing' || checks.hsts === 'missing')
        return 'HTTPS is fine. ' + notes + ' below about weaker security headers.';
    return 'HTTPS and security headers look fine.' + below;
}



// ── Detect compatible forms ──────────────────────────────────────
// The popup only appears when a VISIBLE field on the page asks for at
// least one of: Malaysian IC, credit card, or phone number.
// A sign-up form that only asks for email + password stays silent.

// TRIGGER RULE: the popup appears when the page asks for AT LEAST ONE of:
//   IC number · card number · card PIN · phone number
//   or a LOGIN with email / phone number + password.
// Change to 'all' to show it only when IC + card + phone are ALL asked for.
const TRIGGER_RULE = 'any';
const ALL_TYPES = ['ic', 'card', 'phone'];

const FIELD_RULES = {
    ic:    /\b(ic|nric|mykad|my kad|mykid|kp|ic no|id no)\b|ic[\s_.-]?(no|num|number)|identity|identification|kad pengenalan|no\.? ?kp|new ic|id number|id type|passport/,
    card:  /card[\s_.-]?(no|num|number)|cardnumber|\bcc[\s_-]?(no|num|number)\b|cc-number|credit|debit|atm card|kad kredit|kad debit|no\.? ?kad/,
    phone: /phone|mobile|telefon|handphone|\btel\b|\bhp\b|msisdn|contact[\s_-]?(no|number)|no\.? ?tel|bimbit/
};

// Collect every root to search: the page, open shadow roots (web components)
// and same-origin iframes. Cross-origin iframes run their own copy of
// SensiGuard (all_frames in manifest) and report back.
function allRoots(root = document, out = []) {
    out.push(root);
    root.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) allRoots(el.shadowRoot, out);
        if (el.tagName === 'IFRAME') {
            try { if (el.contentDocument) allRoots(el.contentDocument, out); } catch (e) {}
        }
    });
    return out;
}

// Short visible text right next to a field (labels that are just a <div> or <span>)
const FIELD_SEL = 'input:not([type=hidden]):not([type=submit]):not([type=button]), select, textarea';

function nearbyText(el) {
    // Only use text that belongs to THIS field: stop climbing as soon as
    // the container also holds another field (so "Card PIN" text never
    // leaks into the IC box next to it).
    const bits = [];
    let node = el, steps = 0;
    while (node && node.parentElement && steps < 3) {
        let sib = node.previousElementSibling, n = 0;
        while (sib && n < 2) {
            if (sib.matches(FIELD_SEL) || sib.querySelector(FIELD_SEL)) break;
            const t = (sib.innerText || sib.textContent || '').trim();
            if (t && t.length < 80) bits.push(t);
            sib = sib.previousElementSibling; n++;
        }
        const parent = node.parentElement;
        if (parent.querySelectorAll(FIELD_SEL).length > 1) break;
        node = parent; steps++;
        const own = (node.innerText || '').trim();
        if (own && own.length < 80) bits.push(own);
    }
    return bits.join(' ');
}

// Collect every piece of text that describes an input field
function describeField(el) {
    const root = el.getRootNode();
    const parts = [el.name, el.id, el.placeholder, el.autocomplete, el.title,
                   el.getAttribute('aria-label'), el.getAttribute('data-testid'), el.getAttribute('formcontrolname')];
    if (el.id && root.querySelector) {
        const lab = root.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (lab) parts.push(lab.innerText);
    }
    const wrap = el.closest('label');
    if (wrap) parts.push(wrap.innerText);
    const by = el.getAttribute('aria-labelledby');
    if (by && root.getElementById) by.split(' ').forEach(id => { const n = root.getElementById(id); if (n) parts.push(n.innerText); });
    parts.push(nearbyText(el));
    // split camelCase (icNumber → ic Number) so word rules match
    const raw = parts.filter(Boolean).join(' ');
    return (raw + ' ' + raw.replace(/([a-z])([A-Z])/g, '$1 $2')).toLowerCase();   // keep "MyKad" AND "My Kad"
}

// Returns the data types THIS page asks for right now, e.g. ['ic','phone']
function detectRequiredFields() {
    const found = new Set();
    for (const root of allRoots()) {
        const inputs = root.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]):not([type=button]):not([type=file])');
        for (const el of inputs) {
            if (!isVisible(el)) continue;
            const ac = (el.autocomplete || '').toLowerCase();
            if (el.type === 'tel' || ac.startsWith('tel'))  found.add('phone');
            if (ac.startsWith('cc-number'))                   found.add('card');
            const text = describeField(el);
            // Card PIN box → counts as card data
            if (/\bpin\b|kod pin|nombor pin/.test(text) && !/password|kata laluan/.test(text)) { found.add('pin'); continue; }
            // A normal password box is never counted as IC / card / phone
            if (el.type === 'password') continue;
            for (const [type, rule] of Object.entries(FIELD_RULES)) {
                if (rule.test(text)) found.add(type);
            }
        }
        // ID-type dropdown with MyKad / NRIC = the site asks for an IC number
        root.querySelectorAll('select').forEach(sel => {
            if (isVisible(sel) && [...sel.options].some(o => /mykad|nric|new ic|kad pengenalan/i.test(o.text))) found.add('ic');
        });
        // Card number split into 4 boxes of 4 digits
        root.querySelectorAll('input[maxlength="4"]').forEach(el => {
            const group = el.parentElement && el.parentElement.parentElement;
            if (group && group.querySelectorAll('input[maxlength="4"]').length >= 4) found.add('card');
        });
    }
    if (isLoginForm() && hasEmailOrPhoneLogin()) found.add('login');
    return [...found];
}

// Login box asks for email or phone number (not a plain username)
function hasEmailOrPhoneLogin() {
    const pw = [...document.querySelectorAll('input[type=password]')].find(isVisible);
    if (!pw) return false;
    const box = pw.closest('form') || pw.closest('[role=dialog], .modal, section, main') || document.body;
    return [...box.querySelectorAll('input:not([type=password]):not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit])')]
        .filter(isVisible)
        .some(el => el.type === 'email' || el.type === 'tel' ||
                    /e-?mail|emel|phone|mobile|telefon|bimbit|\bhp\b/.test(describeField(el)));
}

// Remember what this site asked for across the steps of its sign-up
// (banks often ask IC on step 1, card on step 2, phone on step 3).
// Kept per website, per tab, and cleared when the tab is closed.
function rememberFields(types) {
    let seen = [];
    try { seen = JSON.parse(sessionStorage.getItem('sensiguard-seen') || '[]'); } catch (e) {}
    const merged = [...new Set([...seen, ...types])];
    try { sessionStorage.setItem('sensiguard-seen', JSON.stringify(merged)); } catch (e) {}
    return merged;
}

function triggerMet(types) {
    return TRIGGER_RULE === 'all'
        ? ALL_TYPES.every(t => types.includes(t) || (t === 'card' && types.includes('pin')))
        : types.length > 0;
}

// ── Detect a LOGIN form ─────────────────────────────────────────
// Login = exactly ONE visible password box, and the button / heading
// near it is about logging in (not signing up / registering).
const LOGIN_WORDS  = /log ?in|sign ?in|log masuk|masuk|online banking|internet banking/;
const SIGNUP_WORDS = /sign ?up|register|daftar|create (an )?account|join now|confirm password|re-?enter password/;

function isLoginForm() {
    const pw = [...document.querySelectorAll('input[type=password]')].filter(isVisible);
    if (pw.length !== 1) return false;               // 0 = no login, 2+ = sign-up with confirm password

    // Look at the form (or nearest container) around the password box
    const box = pw[0].closest('form') || pw[0].closest('[role=dialog], .modal, section, main') || document.body;
    const buttons = [...box.querySelectorAll('button, input[type=submit], [role=button], a')]
        .filter(isVisible).map(b => (b.innerText || b.value || '').toLowerCase()).join(' ');
    const headings = [...box.querySelectorAll('h1, h2, h3, legend')]
        .map(h => h.innerText.toLowerCase()).join(' ');
    const context = buttons + ' ' + headings + ' ' + document.title.toLowerCase() + ' ' + location.pathname.toLowerCase();

    if (SIGNUP_WORDS.test(headings + ' ' + location.pathname.toLowerCase())) return false;
    return LOGIN_WORDS.test(context) || !SIGNUP_WORDS.test(buttons);
}

function detectCompatibleForms() {
    return detectRequiredFields().length > 0;
}

// Helper: check if an element is actually visible to the user
function isVisible(el) {
    if (!el) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    const view  = (el.ownerDocument && el.ownerDocument.defaultView) || window;   // works inside iframes too
    const style = view.getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

// ── Detect PII in a value ────────────────────────────────────────
// Accepts any format the user types: with hyphens, spaces, or none.
function detectPII(value) {
    if (/\b\d{6}[\s-]?\d{2}[\s-]?\d{4}\b/.test(value))            return 'ic';
    const cardMatch = value.match(/\b\d(?:[\s-]?\d){12,18}\b/);
    if (cardMatch) {
        const n = cardMatch[0].replace(/\D/g, '').length;
        if (n >= 13 && n <= 19) return 'card';
    }
    if (/\b(?:\+?60[\s-]?)?0?1\d[\s-]?\d{3,4}[\s-]?\d{4}\b/.test(value)) return 'phone';
    return null;
}

// Build the popup sample in the SAME format the user typed.
// 990101145678  → ********5678
// 990101-14-5678 → ******-**-5678
function maskSample(value) {
    const total = (value.match(/\d/g) || []).length;
    let seen = 0;
    return value.replace(/\d/g, d => (++seen > total - 4 ? d : '*'));
}

// ── Scan input on typing ─────────────────────────────────────────
// IMPORTANT: we never change el.value. The website still receives
// exactly what the user typed. We only hide it ON SCREEN with CSS.
const maskedFields = new WeakSet();

// Chrome can only hide text as dots (•). To show asterisks (*) instead,
// we make the real text invisible and draw a "*" layer on top of the box.
// The real value inside the input is NEVER changed.
const overlays = new Map();   // input element → overlay div

function hideOnScreen(el, on) {
    if (!on) {
        const ov = overlays.get(el);
        if (ov) { ov.remove(); overlays.delete(el); }
        el.style.removeProperty('color');
        el.style.removeProperty('-webkit-text-fill-color');
        el.style.removeProperty('caret-color');
        return;
    }

    let ov = overlays.get(el);
    if (!ov) {
        const cs = getComputedStyle(el);
        const textColor = cs.color;   // save BEFORE making the text transparent
        el.style.setProperty('caret-color', textColor, 'important');   // keep the cursor visible
        el.style.setProperty('color', 'transparent', 'important');
        el.style.setProperty('-webkit-text-fill-color', 'transparent', 'important');

        ov = document.createElement('div');
        ov.className = 'sensiguard-mask';
        ov.style.cssText = `
            position: fixed; pointer-events: none; overflow: hidden;
            z-index: 2147483646; box-sizing: border-box; background: transparent;
            display: flex; align-items: ${el.tagName === 'TEXTAREA' ? 'flex-start' : 'center'};
            white-space: ${el.tagName === 'TEXTAREA' ? 'pre-wrap' : 'pre'};
            color: ${textColor}; font: ${cs.font}; letter-spacing: ${cs.letterSpacing};
            text-align: ${cs.textAlign};
            justify-content: ${cs.textAlign === 'center' ? 'center' : cs.textAlign === 'right' ? 'flex-end' : 'flex-start'};
            padding: ${cs.paddingTop} ${cs.paddingRight} ${cs.paddingBottom} ${cs.paddingLeft};
            border: solid transparent;
            border-width: ${cs.borderTopWidth} ${cs.borderRightWidth} ${cs.borderBottomWidth} ${cs.borderLeftWidth};
        `;
        ov.appendChild(document.createElement('span'));
        document.documentElement.appendChild(ov);
        overlays.set(el, ov);
    }
    ov.firstChild.textContent = maskSample(el.value);   // e.g. ******-**-5678
    placeOverlay(el, ov);
}

// Is the input box really on top, or is a website pop-up / dark mask covering it?
function isOnTop(el, r) {
    const points = [[r.left + r.width / 2, r.top + r.height / 2], [r.left + 4, r.top + 4], [r.right - 4, r.bottom - 4]];
    return points.some(([x, y]) => {
        if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return false;
        const hit = document.elementFromPoint(x, y);   // overlay ignores clicks, so it is never "hit"
        return hit && (hit === el || el.contains(hit) || (hit.shadowRoot && hit.contains(el)) || hit.closest('label') === el.closest('label') && hit.closest('label'));
    });
}

function placeOverlay(el, ov) {
    if (!el.isConnected || !isVisible(el)) { ov.style.display = 'none'; return; }
    const r = el.getBoundingClientRect();
    if (!isOnTop(el, r)) { ov.style.display = 'none'; return; }   // something covers the box → hide the * layer
    Object.assign(ov.style, {
        display: 'flex',
        left: r.left + 'px', top: r.top + 'px',
        width: r.width + 'px', height: r.height + 'px'
    });
    ov.firstChild.style.transform = `translateX(${-el.scrollLeft}px)`;
}

function repositionAll() {
    overlays.forEach((ov, el) => {
        if (!el.isConnected) { ov.remove(); overlays.delete(el); return; }
        placeOverlay(el, ov);
    });
}
window.addEventListener('scroll', repositionAll, true);
window.addEventListener('resize', repositionAll);
setInterval(repositionAll, 250);   // follows boxes that move (animations, pop-ups)

function scanAndMask(event) {
    if (!isWatching) return;
    const el = (event.composedPath && event.composedPath()[0]) || event.target;
    if (!el || (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA')) return;
    if (el.type === 'password') return;

    const type = detectPII(el.value);

    if (!type) {
        if (maskedFields.has(el)) { hideOnScreen(el, false); maskedFields.delete(el); }
        return;
    }

    hideOnScreen(el, autoMask);
    if (maskedFields.has(el)) return; // already counted this field
    maskedFields.add(el);

    maskedCount++;
    const sample = maskSample(el.value.trim());
    if (IS_TOP) lastMasked = { type, sample };
    updateBannerCount(sample);
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'maskedUpdate', count: maskedCount, type, sample }).catch(() => {});
    }
}

document.addEventListener('input', scanAndMask);

// ── Show floating banner ─────────────────────────────────────────
function showBanner(status, reasons, goodText) {
    if (window.top !== window) return;
    removeBanner();

    const LOOK = {
        high:    { bg: 'linear-gradient(160deg,#d32f2f,#9a1b1b)', icon: '⛔', title: 'High risk site',
                   text: 'Why: ' + reasons.join('; ') + '. Advice: do not enter IC or credit card details here.' },
        caution: { bg: 'linear-gradient(160deg,#d4691f,#a3440b)', icon: '⚠️', title: 'Use caution',
                   text: 'Why: ' + reasons.join('; ') + '.' + (/protection/.test(reasons.join(' ')) ? '' : ' This site has weaker protection.') + ' Advice: check the website address carefully before entering personal data.' },
        strong:  { bg: 'linear-gradient(160deg,#23934f,#14663a)', icon: '✅', title: 'No danger found',
                   text: (goodText || 'No warning signs were found.') + ' Stay careful: this does not guarantee the site is safe.' }
    };
    const look = LOOK[status] || LOOK.caution;
    const bg = look.bg, icon = look.icon, title = look.title, bodyText = look.text;

    // Build the banner with DOM nodes only (no innerHTML)
    const el = (tag, css, text) => {
        const n = document.createElement(tag);
        if (css)  n.style.cssText = css;
        if (text != null) n.textContent = text;
        return n;
    };
    const FONT = "font-family:'Inter','Segoe UI',sans-serif;";

    bannerEl = el('div', `
        all: initial; position: fixed; top: 18px; right: 18px; z-index: 2147483647;
        background: ${bg}; color: #fff; ${FONT} font-size: 13px;
        border-radius: 12px; padding: 14px 16px 12px; width: 290px;
        box-shadow: 0 6px 24px rgba(0,0,0,0.22); display: block; box-sizing: border-box;`);
    bannerEl.id = 'sensiguard-banner';

    const top   = el('div', 'display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;');
    const left  = el('div', 'display:flex;align-items:center;gap:8px;');
    left.append(el('span', 'font-size:18px;', icon),
                el('span', 'font-size:14px;font-weight:700;color:#fff;' + FONT, title));
    const close = el('span', 'cursor:pointer;font-size:16px;color:rgba(255,255,255,0.75);font-family:sans-serif;padding:0 4px;line-height:1;', '✕');
    close.id = 'sg-close';
    close.addEventListener('click', removeBanner);
    top.append(left, close);

    const body   = el('div', 'font-size:11px;color:rgba(255,255,255,0.9);line-height:1.5;' + FONT, bodyText);
    const bottom = el('div', 'margin-top:10px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.25);display:flex;align-items:center;gap:6px;');
    const count  = el('span', 'margin-left:auto;font-size:10px;color:rgba(255,255,255,0.7);' + FONT, 'Masked: 0');
    count.id = 'sg-count';
    bottom.append(el('span', 'font-size:11px;font-weight:600;color:#fff;' + FONT, '🛡 SENSIGUARD'), count);

    bannerEl.append(top, body, bottom);

    (document.body || document.documentElement).appendChild(bannerEl);

    // Slide-in animation via the Web Animations API (no <style> injected into the page)
    try {
        bannerEl.animate([{ opacity: 0, transform: 'translateY(-14px)' }, { opacity: 1, transform: 'translateY(0)' }],
                         { duration: 350, easing: 'ease' });
    } catch (e) {}

    // Auto-hide after 8 seconds
    setTimeout(() => {
        if (bannerEl) {
            bannerEl.style.transition = 'opacity 0.5s';
            bannerEl.style.opacity = '0';
            setTimeout(removeBanner, 500);
        }
    }, 8000);
}

function updateBannerCount(sample) {
    const countEl = document.getElementById('sg-count');
    if (countEl) countEl.textContent = 'Masked: ' + maskedCount + (sample ? '  (e.g. ' + sample + ')' : '');
}

function removeBanner() {
    if (bannerEl) { bannerEl.remove(); bannerEl = null; }
    const old = document.getElementById('sensiguard-banner');
    if (old) old.remove();
}

// ══════════════════════════════════════════════════════════════════
// AUTO WATCHER
// Many sites (Shopee, Lazada, banks) build their login / sign-up form
// with JavaScript AFTER the page loads, or open it in a pop-up window.
// So instead of checking only once, SensiGuard re-checks whenever new
// elements appear on the page or the URL changes.
// ══════════════════════════════════════════════════════════════════
let protectionOn = false;
let shownForUrl  = null;   // URL we already showed the banner for
let recheckTimer = null;
let frameFields  = [];     // fields found inside cross-origin iframes

let runAutoCheck = function () {
    if (!protectionOn) return;
    if (shownForUrl === location.href) return;      // already shown on this page

    const fields = rememberFields(detectRequiredFields().concat(frameFields));
    if (!triggerMet(fields)) return;                 // site has not asked for all 3 yet
    shownForUrl = location.href;

    chrome.runtime.sendMessage({ action: 'getHeaders' }, (headers) => {
        if (chrome.runtime.lastError) headers = null;
        const t0 = performance.now();
        const { status, reasons, info, checks } = checkPageSecurity(headers);
        checks.goodText = strongText(checks);
        const scanMs = (performance.now() - t0).toFixed(3);
        maskedCount  = 0;

        showBanner(status, reasons, strongText(checks));
        chrome.runtime.sendMessage({ action: 'scanResult', status, reasons, info, checks, fields, scanMs }).catch(() => {});
    });
};

function scheduleCheck() {
    clearTimeout(recheckTimer);
    recheckTimer = setTimeout(() => runAutoCheck(), 500);   // wait until the page stops changing
}

function startProtection(mask) {
    protectionOn = true;
    isWatching   = true;            // auto-mask works whenever protection is ON
    autoMask     = mask !== false;
    shownForUrl  = null;
    scheduleCheck();
}

function stopProtection() {
    protectionOn = false;
    lastMasked   = null;
    isWatching   = false;
    shownForUrl  = null;
    document.querySelectorAll('input, textarea').forEach(el => {
        if (maskedFields.has(el)) hideOnScreen(el, false);
    });
    removeBanner();
}

if (typeof chrome !== 'undefined' && chrome.storage) {
    // Read saved settings when the page opens
    chrome.storage.local.get(['isOn', 'autoMask'], (d) => {
        if (d.isOn !== false) startProtection(d.autoMask);
    });

    // React instantly when the user flips a switch in the popup
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.isOn) {
            changes.isOn.newValue !== false
                ? chrome.storage.local.get('autoMask', d => startProtection(d.autoMask))
                : stopProtection();
        }
        if (changes.autoMask) {
            autoMask = changes.autoMask.newValue !== false;
            document.querySelectorAll('input, textarea').forEach(el => {
                if (maskedFields.has(el)) hideOnScreen(el, autoMask);
            });
        }
    });
}


const FIELD_TYPES = ['ic', 'card', 'phone', 'pin', 'login'];
const MASK_TYPES  = ['ic', 'card', 'phone'];

if (!IS_TOP) {
    // Inside an iframe (e.g. a bank's embedded form): report fields upward only
    runAutoCheck = function () {
        if (!protectionOn) return;
        const f = detectRequiredFields();
        if (f.length) chrome.runtime.sendMessage({ action: 'frameFields', fields: f }).catch(() => {});
    };
} else if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    // Only the top page listens. Accept messages ONLY from this extension's
    // own pages (background / popup). Chrome sets sender.url; for another
    // content script it would be a web address, not chrome-extension://.
    const EXT_ORIGIN = chrome.runtime.getURL('');
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (sender.id !== chrome.runtime.id) return;
        if (typeof sender.url !== 'string' || !sender.url.startsWith(EXT_ORIGIN)) return;
        if (!msg || typeof msg.action !== 'string') return;

        if (msg.action === 'frameFields' && Array.isArray(msg.fields)) {
            const add = msg.fields.filter(f => FIELD_TYPES.includes(f));
            frameFields = [...new Set([...frameFields, ...add])];
            scheduleCheck();
            return;
        }
        if (msg.action === 'maskedFromFrame' && MASK_TYPES.includes(msg.type) && /^[\d*\s-]{1,40}$/.test(String(msg.sample))) {
            lastMasked = { type: msg.type, sample: String(msg.sample) };
            return;
        }
        if (msg.action === 'getMasked') {                      // popup asks for the masked notice
            sendResponse(protectionOn ? lastMasked : null);
            return;
        }
    });
}

// Re-check when elements appear OR are shown/hidden (step-by-step forms
// often just switch a class or style instead of adding new elements)
new MutationObserver(() => { if (protectionOn) scheduleCheck(); })
    .observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style', 'hidden'] });

// Safety net: re-check every 2 seconds until the popup has been shown
setInterval(() => { if (protectionOn && shownForUrl !== location.href) runAutoCheck(); }, 2000);

// Re-check when the URL changes without a reload (single-page apps)
let lastUrl = location.href;
setInterval(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        shownForUrl = null;
        scheduleCheck();
    }
}, 700);
