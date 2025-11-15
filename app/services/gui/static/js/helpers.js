/**
 * Pause execution for a specified number of milliseconds.
 * @param {number} [timeoutMs=200] - Delay duration in milliseconds.
 * @returns {Promise<void>} Promise that resolves after the timeout.
 */
function delay(timeoutMs = 200) {
    return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

/**
 * Convert snake_case string to space-separated words.
 * @param {string} [key=''] - Input string.
 * @returns {string} Formatted string.
 */
function formatStatsKey(key = '') {
    return key.trim().replaceAll('_', ' ');
}

/**
 * Convert snake_case string to Capitalized Words.
 * @param {string} key - Input string.
 * @returns {string} Formatted string.
 */
function formatMetricKey(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
}

/**
 * Check if a key represents a timestamp.
 * @param {string} key - Key to check.
 * @returns {boolean} True if key is a timestamp key.
 */
function isTimestamp(key) {
    return ['last_updated', 'start_time'].includes(key.trim().toLowerCase());
}

/**
 * Format a timestamp as a locale string.
 * @param {string|number} input - Timestamp as string or number.
 * @returns {string} Formatted date string or empty string if invalid.
 */
function formatTimestamp(input) {
    if (!input) return '';
    let date;
    if (typeof input === 'number') {
        date = new Date(input < 1e12 ? input * 1000 : input);
    } else if (typeof input === 'string') {
        date = new Date(input.replace(' ', 'T'));
    } else {
        return '';
    }
    if (isNaN(date.getTime())) return '';
    return date.toLocaleString('sv-SE');
}

/**
 * Filter out unwanted statistics values.
 * @param {*} value - Value to check.
 * @returns {boolean} True if value should be kept.
 */
function filterUnnendedStats(value) {
    if (value == null) return false;
    if (typeof value === 'string' && value.toLowerCase() === 'id') return false;
    if (typeof value === 'number' && value <= 0) return false;
    return true;
}

/**
 * Get CSS class for a row based on blacklists/whitelists.
 * @param {string} query - Query string.
 * @param {string[]} blacklists - Array of blacklisted strings.
 * @param {string[]} whitelists - Array of whitelisted strings.
 * @returns {string} CSS class string.
 */
function getRowPredictionClass(query = '', blacklists = [], whitelists = []) {
    const queryLowerCased = query.toLowerCase();
    if (blacklists.includes(queryLowerCased)) return 'bg-danger bg-opacity-10';
    if (whitelists.includes(queryLowerCased)) return 'bg-success bg-opacity-10';
    return '';
}

/**
 * Get CSS badge class based on prediction probability.
 * @param {number} [prob=0.5] - Probability value (0-1).
 * @returns {string} Badge CSS class string.
 */
function getPredictionBadgeClass(prob = 0.5) {
    if (prob < 0.25) return 'badge bg-success text-white';
    if (prob > 0.9) return 'badge bg-danger text-white';
    return 'badge bg-secondary text-white';
}

/**
 * Generic fetch wrapper for API calls.
 * @param {Object} options - Fetch options.
 * @param {string} [options.method='POST'] - HTTP method.
 * @param {string} options.token - Authorization token.
 * @param {Object} options.body - Request payload.
 * @param {number} [options.timeout=10000] - Timeout in milliseconds.
 * @param {boolean} [options.keepalive=false] - Keepalive flag.
 * @returns {Promise<Response>} Fetch API response.
 */
async function fetcher({ method = 'POST', token, body, timeout = 10000, keepalive = false }) {
    return await fetch('/api', {
        method,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeout),
        keepalive,
    });
}
