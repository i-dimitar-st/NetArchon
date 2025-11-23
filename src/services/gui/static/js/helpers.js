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
 * Build common API request headers.
 * @param {string} token - Authorization bearer token.
 * @returns {Object} Headers object.
 */
function buildApiHeaders(token) {
    return {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
    };
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
        headers: buildApiHeaders(token),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeout),
        keepalive,
    });
}

/**
 * Parse a single NDJSON line safely.
 * @param {string} line - JSON string to parse.
 * @returns {Object|null} Parsed object or null if parsing fails.
 */
function parseNdjsonLineToObj(line) {
    if (!line.trim()) return null;
    try {
        return JSON.parse(line);
    } catch (err) {
        console.error('Failed to parse NDJSON chunk:', line, err);
        return null;
    }
}

/**
 * Split buffer into complete lines and remaining buffer.
 * @param {string} buffer - Data buffer.
 * @returns {Object} Object with `lines` array and `remaining` buffer.
 */
function splitBufferIntoCompleteLines(buffer) {
    const lines = buffer.split(/\r?\n/);
    const remaining = lines.pop();
    return { lines, remaining };
}

/**
 * Fetch wrapper for streaming NDJSON responses from an API endpoint.
 * This function performs a POST (or other method) request to the `/api` endpoint
 * and returns an async generator that yields parsed JSON objects line by line
 * from an NDJSON (newline-delimited JSON) response stream.
 * @async
 * @generator
 * @param {Object} options - Options for the fetch request.
 * @param {string} [options.method='POST'] - HTTP method to use.
 * @param {string} options.token - Authorization token (Bearer token).
 * @param {Object} options.body - Request payload to be JSON-stringified.
 * @param {number} [options.timeout=600000] - Request timeout in milliseconds (default 10 min).
 * @yields {Object} Parsed JSON object for each NDJSON line received from the server.
 * @throws {Error} If the fetch fails, the response is not OK, or no body is returned.
 */
async function* fetcherStreaming({ method = 'POST', token, body, timeout = 600000 }) {
    const res = await fetch('/api', {
        method,
        headers: buildApiHeaders(token),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeout),
        keepalive: true,
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    if (!res.body) throw new Error('No response body for streaming');

    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const { lines, remaining } = splitBufferIntoCompleteLines(buffer);
        buffer = remaining;

        for (const line of lines) {
            const parsedNdjsonLineObj = parseNdjsonLineToObj(line);
            if (parsedNdjsonLineObj !== null) {
                console.info('Parsed NDJSON line:', parsedNdjsonLineObj);
                yield parsedNdjsonLineObj;
            }
        }
    }

    const lastParsedNdjsonLineObj = parseNdjsonLineToObj(buffer);
    if (lastParsedNdjsonLineObj !== null) {
        console.info('Last parsed NDJSON line:', lastParsedNdjsonLineObj);
        yield lastParsedNdjsonLineObj;
    }
}
