function delay(timeoutMs = 200) {
    return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

function formatStatsKey(key = '') {
    return key.trim().replaceAll('_', ' ');
}

function formatTimestamp(timestamp) {
    return timestamp ? new Date(timestamp * 1000).toLocaleString() : '';
}

function filterUnnendedStats(value) {
    return Boolean(value !== 'id' && value != null && value > 0);
}

function getDomainPredictionsMap(predictions = []) {
    return predictions.reduce((map, each) => {
        if (each.domain) map[each.domain.toLowerCase()] = each.probability;
        return map;
    }, {});
}

function getRowPredictionClass(query = '', blacklists = [], whitelists = []) {
    const queryLowerCased = query.toLowerCase();
    if (blacklists.includes(queryLowerCased)) return 'bg-danger bg-opacity-25 rounded-1';
    if (whitelists.includes(queryLowerCased)) return 'bg-success bg-opacity-25 rounded-1';
    return '';
}

function getPredictionBadgeClass(prob = 0.5) {
    if (prob < 0.25) return 'badge bg-success text-white';
    if (prob > 0.9) return 'badge bg-danger text-white';
    return 'badge bg-secondary text-dark';
}

async function fetcher({ method = 'POST', token, type, category, payload, timeout = 10000 }) {
    return await fetch('/api', {
        method,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ type, category, payload }),
        signal: AbortSignal.timeout(timeout),
    });
}
