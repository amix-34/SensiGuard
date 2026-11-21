// SensiGuard - detect-libs.js
// Runs in the PAGE's own world (not the isolated extension world),
// because only there can we read window.jQuery, window.angular, etc.
// It only READS version numbers. It never touches what the user types.
// SECURITY: it never calls chrome.* APIs, sends nothing over the network,
// and only writes plain version strings (content.js validates them again).

(function () {
    'use strict';
    const clean = (v) => { const s = String(v == null ? '' : v); return /^\d{1,3}(\.\d{1,4}){0,3}$/.test(s) ? s : null; };
    function readVersions() {
        const w = window, found = [];
        try { if (w.jQuery && w.jQuery.fn && w.jQuery.fn.jquery) found.push({ name: 'jQuery', version: w.jQuery.fn.jquery }); } catch (e) {}
        try { if (w.angular && w.angular.version) found.push({ name: 'AngularJS', version: w.angular.version.full }); } catch (e) {}
        try {
            const bs = (w.bootstrap && w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION) ||
                       (w.jQuery && w.jQuery.fn && w.jQuery.fn.tooltip && w.jQuery.fn.tooltip.Constructor && w.jQuery.fn.tooltip.Constructor.VERSION);
            if (bs) found.push({ name: 'Bootstrap', version: bs });
        } catch (e) {}
        try { if (w._ && w._.VERSION && typeof w._.flatMapDeep === 'function') found.push({ name: 'Lodash', version: w._.VERSION }); } catch (e) {}
        return found.filter(f => clean(f.version)).map(f => ({ name: f.name, version: clean(f.version) }));
    }

    // content.js fires this event; we answer by writing to a data attribute.
    // DOM events run synchronously, so content.js can read the answer right after.
    document.addEventListener('sensiguard-request-libs', function () {
        document.documentElement.setAttribute('data-sensiguard-libs', JSON.stringify(readVersions()));
    });
})();
