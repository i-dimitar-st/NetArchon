function HistoryDomains({ dnsHistory, token }) {
    const [history, setHistory] = React.useState(dnsHistory || []).sort((a, b) => b.created - a.created);

    const showLoading = () => (document.getElementById('loadingOverlay').style.display = 'flex');
    const hideLoading = () => (document.getElementById('loadingOverlay').style.display = 'none');

    const handleClear = () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;

        showLoading();
        fetch('/api', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ type: 'clear-dns-history', payload: null }),
        })
            .then((res) => {
                if (!res.ok) throw new Error('Server error');
                return res.json();
            })
            .then((jsonRes) => {
                if (!jsonRes.success) throw new Error(jsonRes.error || 'Unknown error');
                setHistory([]);
            })
            .catch(() => alert('Failed to clear DNS history'))
            .finally(hideLoading);
    };

    const formatTimestamp = (timestamp) => {
        if (!timestamp) return '';
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    };

    return (
        <div className="card mt-4 overflow-hidden">
            <div className="card-header d-flex align-items-center justify-content-between">
                <h5 className="mb-0 d-inline-flex">DNS Query History</h5>
                <button className="btn btn-sm btn-danger" onClick={handleClear}>
                    Clear
                </button>
            </div>
            <div className="card-body p-2" style={{ maxHeight: 300, overflowY: 'auto' }}>
                {history.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No history</em>
                    </div>
                ) : (
                    history.map((item, idx) => {
                        const query = item?.query || '(unknown)';
                        const counter = item?.query_counter || 0;
                        const timestamp = formatTimestamp(item?.created);
                        return (
                            <div
                                key={idx}
                                className="d-flex align-items-center justify-content-between bg-light border rounded-pill px-3 py-2 mb-2"
                                data-query={query.toLowerCase()}
                            >
                                <span className="text-truncate" style={{ maxWidth: '40%', wordBreak: 'break-word' }}>
                                    {query.toLowerCase()}
                                </span>
                                <span className="badge bg-primary">{counter}</span>
                                <span className="text-muted" style={{ fontSize: '0.8rem' }}>
                                    {timestamp}
                                </span>
                            </div>
                        );
                    })
                )}
            </div>
        </div>
    );
}
