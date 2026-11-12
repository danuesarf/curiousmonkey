// Runs before the first paint so a light-theme user never sees the dark page flash. Kept tiny and classic (not a
// module) on purpose; js/theme.js does the rest once the app loads.
try { if (localStorage.getItem('cm-theme') === 'light') document.documentElement.dataset.theme = 'light'; } catch { /* storage off */ }
