function NoMetrics() {
    return <div className="alert alert-warning mb-0">No metrics available</div>;
}

function MetricSideBar({ metrics, activeIndex, onSelect }) {
    return (
        <div className="col-md-3">
            <div className="nav flex-column nav-pills p-0 rounded-0" role="tablist">
                {metrics.map((item, i) => (
                    <button
                        key={i}
                        className={`nav-link text-start text-uppercase rounded-0 ${i === activeIndex ? 'active' : ''}`}
                        onClick={() => onSelect(i)}
                    >
                        {item.label.replace(/_/g, ' ')}
                    </button>
                ))}
            </div>
        </div>
    );
}

function MetricContent({ item, maxValue }) {
    if (!item) return null;

    return (
        <div className="col-md-9">
            <div className="card-body p-3">
                {Object.entries(item.metrics).map(([key, value], idx) => {
                    const widthPercent = Math.min(parseInt((value / maxValue) * 100), 100) + '%';
                    return (
                        <div key={idx} className="mb-2">
                            <div className="d-flex justify-content-between small" title={`Max: ${maxValue} ms`}>
                                <span className="text-uppercase small text-muted">{formatMetricKey(key)}</span>
                                <span>
                                    <span className="me-1">{value.toFixed(0)}</span>
                                    <span className="text-muted small">ms</span>
                                </span>
                            </div>
                            <div className="progress" style={{ height: '6px' }}>
                                <div
                                    className="progress-bar bg-primary"
                                    role="progressbar"
                                    style={{ width: widthPercent }}
                                    aria-valuenow={parseInt(value)}
                                    aria-valuemin="0"
                                    aria-valuemax={parseInt(maxValue)}
                                ></div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function Metrics({ token }) {
    const { useState, useEffect } = React;
    const [metrics, setMetrics] = useState([]);
    const [maxValue, setMaxValue] = useState(2500);
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        (async () => {
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
        })();
    }, [token]);

    const activeItem = metrics[activeIndex];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <h6>Metrics</h6>
            </div>
            <div className="row g-0">
                {metrics.length === 0 ? (
                    <NoMetrics />
                ) : (
                    <>
                        <MetricSideBar metrics={metrics} activeIndex={activeIndex} onSelect={setActiveIndex} />
                        <MetricContent item={activeItem} maxValue={maxValue} />
                    </>
                )}
            </div>
        </div>
    );
}

window.Metrics = Metrics;
