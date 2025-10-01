function HistoryDomains({ token, dnsHistory = [], blacklists = [], whitelists = [], predictions = [] }) {
    const [history, setHistory] = React.useState([...dnsHistory].sort((a, b) => b.created - a.created));
    const [loading, setLoading] = React.useState(false);

    // Create a lookup map for predictions by domain
    const predictionMap = React.useMemo(() => {
        const map = {};
        (predictions || []).forEach((p) => {
            if (p.domain) map[p.domain.toLowerCase()] = p.probability;
        });
        return map;
    }, [predictions]);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const handleClear = async () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;

        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ type: 'clear-dns-history', payload: null }),
            });
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
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ category: 'whitelist', type: 'add', payload: domain }),
            });
            if (!res.ok) throw new Error('Failed to add to whitelist');
            alert(`${domain} added to whitelist`);
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            hideLoading();
        }
    };

    const handleAddToBlacklist = async (domain) => {
        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ category: 'blacklist', type: 'add', payload: domain }),
            });
            if (!res.ok) throw new Error('Failed to add to blacklist');
            alert(`${domain} added to blacklist`);
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            hideLoading();
        }
    };

    const formatTimestamp = (timestamp) => (timestamp ? new Date(timestamp * 1000).toLocaleString() : '');

    const Row = ({ query, counter, timestamp, prediction }) => {
        const isBlacklisted = blacklists.includes(query.toLowerCase());
        const isWhitelisted = whitelists.includes(query.toLowerCase());
        const getPredictionBadgeClass = (prob) => {
            if (prob < 0.25) return 'badge bg-success text-dark';
            if (prob > 0.9) return 'badge bg-danger text-white';
            return 'badge bg-secondary text-dark';
        };

        let rowClass = '';
        if (isBlacklisted) rowClass = 'bg-danger bg-opacity-25 rounded-1';
        if (isWhitelisted) rowClass = 'bg-success bg-opacity-25 rounded-1';

        return (
            <div className={`d-flex align-items-center px-2 py-1 my-1 border-bottom ${rowClass}`}>
                <span className="text-truncate fw-medium" style={{ maxWidth: '30%' }} title={query}>
                    {query.toLowerCase()}
                </span>

                <div className="d-flex align-items-center ms-auto gap-2 flex-wrap">
                    <span className="badge bg-secondary">{counter}</span>
                    {prediction !== undefined && (
                        <span className={`${getPredictionBadgeClass(prediction)}`}>{prediction.toFixed(3)}</span>
                    )}
                    <small className="text-muted text-end" style={{ minWidth: '100px' }}>
                        {timestamp}
                    </small>
                    <button className="btn btn-sm btn-success" onClick={() => handleAddToWhitelist(query)}>
                        Whitelist
                    </button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleAddToBlacklist(query)}>
                        Blacklist
                    </button>
                </div>
            </div>
        );
    };

    return (
        <div className="card mb-4 position-relative" style={{ maxHeight: '500px' }}>
            {loading && (
                <div className="position-absolute top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center bg-light bg-opacity-75">
                    <div className="spinner-border text-primary" role="status">
                        <span className="visually-hidden">Loading...</span>
                    </div>
                </div>
            )}
            <div className="card-header d-flex align-items-center justify-content-between">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0">DNS Query History</h5>
                    <span className="badge bg-secondary">{history.length}</span>
                </div>
                <button className="btn btn-sm btn-primary" onClick={handleClear}>
                    Clear
                </button>
            </div>
            <div className="card-body p-2 overflow-auto" style={{ maxHeight: 300 }}>
                {history.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No history</em>
                    </div>
                ) : (
                    history.map((item, idx) => (
                        <Row
                            key={idx}
                            query={item?.query || '(unknown)'}
                            counter={item?.query_counter || 0}
                            timestamp={formatTimestamp(item?.created)}
                            prediction={predictionMap[item?.query?.toLowerCase()]}
                        />
                    ))
                )}
            </div>
        </div>
    );
}

window.HistoryDomains = HistoryDomains;
