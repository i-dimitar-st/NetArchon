function delay(timeoutMs = 200) {
    return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

function formatStatsKey(key = '') {
    return key.trim().replaceAll('_', ' ');
}

function formatMetricKey(key) {
    if (key.startsWith('p') && !isNaN(key.slice(1))) {
        return `${key.slice(1)}th percentile`;
    }
    return key;
}


function formatTimestamp(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp * 1000);
    const pad = (n) => n.toString().padStart(2, '0');

    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
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
