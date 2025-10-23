function DhcpStats() {
    const { useState, useEffect } = React;
    const [title, setTitle] = useState('Statistics');
    const [stats, setStats] = useState({});
    const [loading, setLoading] = useState(true);
    const [maxValue, setMaxValue] = useState(0);

    useEffect(async () => {
        setLoading(true);
        try {
            const res = await fetcher({ token, category: 'dhcp_leases', type: 'get-stats' });
            const { payload, success } = await res.json();
            if (!success) throw new Error('Could not fetch DNS stats');
            setStats(payload || {});
            setMaxValue(payload.received_total ?? 1);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [token]);

    const isTimestamp = (key) => ['last_updated', 'start_time'].includes(key.trim().toLowerCase());

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <h6>{title}</h6>
            </div>
            <div className="card-body p-3">
                {!loading &&
                    Object.entries(stats)
                        .filter(([key, value]) => filterUnnendedStats(value))
                        .filter(([key, value]) => filterUnnendedStats(key))
                        .filter(([key, value]) => key.toLowerCase() !== 'start_time')
                        .map(([key, value]) => {
                            const widthPercent = Math.min(parseInt((value / maxValue) * 100), 100) + '%';
                            return (
                                <div key={key} className="mb-2">
                                    <div className="d-flex justify-content-between align-items-center">
                                        <div className="text-muted text-capitalize small fw-medium">
                                            {formatStatsKey(key)}
                                        </div>
                                        <div>
                                            <span title={value} className="fw-semibold small">
                                                {key === 'last_updated'
                                                    ? formatTimestamp(value)
                                                    : parseInt((value / maxValue) * 100)}
                                            </span>
                                            {!isTimestamp(key) && <span className="small text-muted ms-1">%</span>}
                                        </div>
                                    </div>
                                    {!isTimestamp(key) && maxValue > 0 && (
                                        <div className="progress">
                                            <div
                                                className="progress-bar"
                                                role="progressbar"
                                                style={{ width: widthPercent }}
                                                aria-valuenow={parseInt(value)}
                                                aria-valuemin="0"
                                                aria-valuemax={parseInt(maxValue)}
                                            ></div>
                                        </div>
                                    )}
                                </div>
                            );
                        })}
            </div>
        </div>
    );
}

window.DhcpStats = DhcpStats;
