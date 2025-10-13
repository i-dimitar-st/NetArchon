function DomainRow({ query, counter, timestamp, prediction = 0.5, blacklists, whitelists, onWhitelist, onBlacklist }) {
    return (
        <div
            className={`d-flex flex-column flex-md-row justify-content-between align-items-center mb-2 p-2 rounded border-bottom ${getRowPredictionClass(
                query,
                blacklists,
                whitelists
            )}`}
        >
            <span
                className={`small me-2 text-truncate ${prediction > 0.95 ? 'text-danger' : 'text-muted'}`}
                title={query}
            >
                {query.toLowerCase()}
            </span>

            <div className="d-flex align-items-center ms-auto gap-2 flex-wrap">
                <span className="badge bg-secondary">{counter}</span>
                {prediction !== undefined && (
                    <span className={getPredictionBadgeClass(prediction)}>{(prediction * 100).toFixed(1)}</span>
                )}
                <small className="text-muted text-end flex-shrink-0" style={{ minWidth: '100px' }}>
                    {timestamp}
                </small>
                <button className="btn btn-sm btn-success" onClick={() => onWhitelist(query)}>
                    Allow
                </button>
                <button className="btn btn-sm btn-danger" onClick={() => onBlacklist(query)}>
                    Block
                </button>
            </div>
        </div>
    );
}

function HistoryDomains({ token, blacklists = [], whitelists = [], predictions = [] }) {
    const { useState, useEffect, useMemo } = React;
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [defaultPrediction, setDefaultPrediction] = useState(0.5);

    const domainPredictionsMap = useMemo(() => getDomainPredictionsMap(predictions), [predictions]);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const sortedHistory = useMemo(() => {
        return [...history].sort((a, b) => {
            const probA = domainPredictionsMap[a?.query?.toLowerCase()] ?? 0.5;
            const probB = domainPredictionsMap[b?.query?.toLowerCase()] ?? 0.5;
            return probB - probA;
        });
    }, [history, domainPredictionsMap]);

    // Handlers
    const handleClear = async () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;
        showLoading();
        await delay();
        try {
            const res = await fetcher({ token, category: 'dns-history', type: 'clear', payload: null });
            if (!res.ok) throw new Error('Server error');
            const jsonRes = await res.json();
            if (!jsonRes.success) throw new Error(jsonRes.error || 'Unknown error');
            setHistory([]);
        } catch {
            alert('Failed to clear DNS history');
        } finally {
            hideLoading();
        }
    };

    const handleAddToWhitelist = async (domain) => {
        showLoading();
        await delay();
        try {
            const res = await fetcher({ token, category: 'whitelist', type: 'add', payload: domain });
            if (!res.ok) throw new Error('Failed to add to whitelist');
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            hideLoading();
        }
    };

    const handleAddToBlacklist = async (domain) => {
        showLoading();
        await delay();
        try {
            const res = await fetcher({ token, category: 'blacklist', type: 'add', payload: domain });
            if (!res.ok) throw new Error('Failed to add to blacklist');
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            hideLoading();
        }
    };

    // Fetch DNS history on mount
    useEffect(() => {
        const fetchAndSetDnsHistory = async () => {
            showLoading();
            await delay();
            try {
                const res = await fetcher({ token, category: 'dns-history', type: 'get' });
                if (!res.ok) throw new Error('Server error');
                const data = await res.json();
                if (!data.success || !Array.isArray(data.payload)) throw new Error('Invalid response');
                setHistory(data.payload);
            } catch (err) {
                console.error(err);
                alert(err.message || 'Error fetching DNS History');
            } finally {
                hideLoading();
            }
        };
        fetchAndSetDnsHistory();
    }, [token]);

    return (
        <div className="card p-0">
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex align-items-center justify-content-between">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold">DNS Query History</h5>
                    <span className="badge bg-primary">{history.length}</span>
                </div>
                <button className="btn btn-sm btn-danger" onClick={handleClear}>
                    Clear
                </button>
            </div>
            <div className="card-body p-2 overflow-auto">
                {sortedHistory.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No history</em>
                    </div>
                ) : (
                    sortedHistory.map((item, idx) => (
                        <DomainRow
                            key={idx}
                            query={item?.query || '(unknown)'}
                            counter={item?.query_counter || 0}
                            timestamp={formatTimestamp(item?.created)}
                            prediction={domainPredictionsMap[item?.query?.toLowerCase()] || defaultPrediction}
                            blacklists={blacklists}
                            whitelists={whitelists}
                            onWhitelist={handleAddToWhitelist}
                            onBlacklist={handleAddToBlacklist}
                        />
                    ))
                )}
            </div>
        </div>
    );
}

window.HistoryDomains = HistoryDomains;
