function MetricCard({ item, maxValue }) {
    return (
        <div className="col-md-4">
            <div className="card">
                <div className="card-header d-flex justify-content-between align-items-center">
                    <h6 className="mb-0 fw-bold text-uppercase d-flex align-items-center">
                        <span className="me-2">{item.label.replace(/_/g, ' ')}</span>
                        <span className="badge bg-primary">{item.qty}</span>
                    </h6>
                </div>
                <div className="card-body p-3">
                    {Object.entries(item.metrics).map(([key, value], idx) => {
                        const widthPercent = Math.min(parseInt((value / maxValue) * 100), 100) + '%';
                        return (
                            <div key={idx}>
                                <div className="d-flex justify-content-between p-2">
                                    <span className="text-uppercase">{key}</span>
                                    <span className="">
                                        {value.toFixed(2)}
                                        <small className="ms-1">ms</small>
                                    </span>
                                </div>
                                <div className="progress" style={{ height: '6px' }}>
                                    <div
                                        className="progress-bar"
                                        role="progressbar"
                                        style={{
                                            backgroundColor: 'var(--primary-color)',
                                            width: widthPercent,
                                        }}
                                        aria-valuenow={parseInt(value)}
                                        aria-valuemin="0"
                                        aria-valuemax={maxValue}
                                    ></div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}

function Metrics({ token }) {
    const { useState, useEffect } = React;
    const [metrics, setMetrics] = useState([]);
    const [maxValue, setMaxValue] = useState(1000);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchNetwork = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'metrics', type: 'get' });
                const json = await res.json();
                if (!json.success) throw new Error('Could not fetch network interfaces');
                setMetrics(json.payload || []);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchNetwork();
    }, [token]);

    return (
        <div className="row g-4">
            <LoadingOverlay visible={loading} />
            {metrics.map((metric) => (
                <MetricCard key={metrics.label} item={metric} maxValue={maxValue} />
            ))}
        </div>
    );
}

window.Metrics = Metrics;
