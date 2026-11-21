# SensiGuard

A Chrome extension (Manifest V3) that helps stop you from leaking personal data online. It watches for forms that ask for Malaysian IC numbers, credit card numbers or phone numbers, hides those digits on screen, and checks whether the website looks safe enough to trust with them.

**Version:** 2.3 | **Requires:** Chrome 111 or newer

## Features

- **Sensitive form detection:** spots visible fields asking for a Malaysian IC (MyKad), credit card number, card PIN, phone number, or an email/phone login. It also works on forms that load late, step-by-step sign-ups, shadow DOM and iframes.
- **Auto-mask on screen:** when you type an IC, card or phone number, the digits are replaced with `*` on screen (for example `******-**-5678`). The real value in the box is never changed, so the website still receives exactly what you typed. You can turn this off in the popup.
- **Website security checks:**
  - HTTPS connection
  - `Content-Security-Policy` (CSP) header
  - `Strict-Transport-Security` (HSTS) header
  - Outdated jQuery, Bootstrap, AngularJS and Lodash versions
  - Warning signs such as forms that submit over plain `http://`
- **Clear risk levels:** a banner on the page and a colour-coded popup show one of three results.

  | Result | Meaning |
  |---|---|
  | High risk (red) | The site does not use HTTPS |
  | Caution (orange) | Both CSP and HSTS are missing, or a form sends data without HTTPS |
  | No danger found (green) | The checks pass. Weak or missing single headers and old libraries are shown as info only |

- **Popup with two tabs:** *Protect* (live status, checks and settings) and *Why it matters* (why IC, card and phone data are sensitive, with reference to Malaysia's PDPA 2010).
- **On/Off switch** and an **Auto-mask** toggle.

## Privacy and security

- All scanning happens on your device. Nothing is sent over the network (the extension's own CSP blocks all connections).
- Typed values are never stored or logged. Only a masked sample is kept in memory so the popup can show it.
- Scan results are kept in `chrome.storage.session` (memory only) and cleared when the tab or browser closes.
- The extension only reads three response headers (CSP, CSP report-only, HSTS). It does not block or change any request.
- No `innerHTML` is used, and every message between parts of the extension is validated.

## Installation

SensiGuard is not on the Chrome Web Store, so load it manually:

1. On this page, click **Code → Download ZIP**, then extract the ZIP.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the extracted folder (the one containing `manifest.json`).
5. Pin SensiGuard from the puzzle-piece menu to see its icon.

> The popup uses the Inter font from a local `fonts/` folder. If that folder is missing, the popup falls back to Segoe UI or the system font and works normally.

## Usage

1. Visit a website that asks for IC, card or phone details, or has a login form.
2. A banner appears at the top right with the site's risk level.
3. Click the SensiGuard icon to see the detailed security checks.
4. Type sensitive numbers as normal. They are masked on screen.
5. Use the power switch in the popup to turn protection on or off.

## Project structure

| File | Purpose |
|---|---|
| `manifest.json` | Extension configuration, permissions and CSP |
| `content.js` | Detects sensitive forms, masks digits, runs the security checks, shows the banner |
| `detect-libs.js` | Runs in the page to read library versions (jQuery, AngularJS, Bootstrap, Lodash) |
| `background.js` | Service worker: reads CSP/HSTS headers and keeps each tab's result |
| `popup.html`, `popup.css`, `popup.js` | The toolbar popup |

## Permissions

- `storage`: save your on/off and auto-mask settings, and per-tab results in memory
- `webRequest` and host permissions for `http://*/*` and `https://*/*`: read security headers and run on web pages

## Limitations

- Masking hides digits on screen only. It does not stop a website from receiving what you type.
- The security checks are warning signs, not a security test. "No danger found" does not guarantee a site is safe.
- SensiGuard helps reduce the risk of exposing your own data. It does not make an organisation PDPA compliant.

## Author

[amix-34](https://github.com/amix-34)

## License

No license has been added yet. Add a `LICENSE` file (for example MIT) if you want others to reuse the code.
