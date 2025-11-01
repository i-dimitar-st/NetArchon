function delay(timeoutMs = 200) {
    return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

function formatStatsKey(key = '') {
    return key.trim().replaceAll('_', ' ');
}

function formatMetricKey(key) {
    return key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (l) => l.toUpperCase());
}

function isTimestamp(key) {
    return ['last_updated', 'start_time'].includes(key.trim().toLowerCase());
}


function formatTimestamp(input) {
    if (!input) return '';
    let date;
    if (typeof input === 'number') {
        date = new Date(input < 1e12 ? input * 1000 : input);
    } else if (typeof input === 'string') {
        const normalized = input.replace(' ', 'T');
        date = new Date(normalized);
    } else {
        return '';
    }
    if (isNaN(date.getTime())) return '';
    return date.toLocaleString('sv-SE');
}

function filterUnnendedStats(value) {
    if (value == null) return false;
    if (typeof value === 'string' && value.toLowerCase() === 'id') return false;
    if (typeof value === 'number' && value <= 0) return false;
    return true;
}


function getRowPredictionClass(query = '', blacklists = [], whitelists = []) {
    const queryLowerCased = query.toLowerCase();
    if (blacklists.includes(queryLowerCased)) return 'bg-danger bg-opacity-10';
    if (whitelists.includes(queryLowerCased)) return 'bg-success bg-opacity-10';
    return '';
}

function getPredictionBadgeClass(prob = 0.5) {
    if (prob < 0.25) return 'badge bg-success text-white';
    if (prob > 0.9) return 'badge bg-danger text-white';
    return 'badge bg-secondary text-white';
}

async function fetcher({ method = 'POST', token, type, category, payload, timeout = 10000 }) {
    return await fetch('/api', {
        method,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ type, category, payload }),
        signal: AbortSignal.timeout(timeout),
    });
}
