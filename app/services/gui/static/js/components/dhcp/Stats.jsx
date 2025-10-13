function Stats({ token }) {
    const { useState, useEffect } = React;
    const [title, setTitle] = useState('Statistics');
    const [metrics, setMetrics] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'dhcp-leases', type: 'get-stats' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch DHCP leases');
                setMetrics(payload || {});
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token]);

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <h6 className="card-header mb-0 fw-bold text-capitalize">{title}</h6>
            <div className="card-body p-3" style={{ overflowY: 'auto' }}>
                {!loading &&
                    Object.entries(metrics)
                        .filter(([key, value]) => filterUnnendedStats(value))
                        .map(([key, value]) => (
                            <div key={key} className="d-flex justify-content-between align-items-center mb-2">
                                <div className="text-muted text-uppercase small fw-medium">{formatStatsKey(key)}</div>
                                <div className="fw-semibold small">
                                    {value > 1000000 ? formatTimestamp(value) : value}
                                </div>
                            </div>
                        ))}
            </div>
        </div>
    );
}

window.Stats = Stats;
