function estimateMean({ p10, p25, p50, p75, p100 }) {
    return (
        0.1 * p10 +
        0.15 * ((p10 + p25) / 2) +
        0.25 * ((p25 + p50) / 2) +
        0.25 * ((p50 + p75) / 2) +
        0.25 * ((p75 + p100) / 2)
    );
}

function MaxMetrics({ maxValue }) {
    return (
        <div className="col-md-4">
            <div className="card border-0 bg-primary">
                <div className="card-body text-white p-2">
                    <span className="text-uppercase fw-semibold text-white-50 small mb-1 me-2">Max</span>
                    <span className="fs-4 fw-bold text-white">
                        {parseInt(maxValue)}
                        <span className="fs-6 ms-1">ms</span>
                    </span>
                </div>
            </div>
        </div>
    );
}

function AverageMetrics({ averageValue }) {
    return (
        <div className="col-md-4">
            <div className="card border-0 bg-primary">
                <div className="card-body text-white p-2">
                    <span className="small fw-semibold opacity-75 text-uppercase mb-1 me-2">Average</span>
                    <span className="fs-4 fw-bold">
                        {parseInt(averageValue)}
                        <span className="fs-6 ms-1">ms</span>
                    </span>
                </div>
            </div>
        </div>
    );
}

function MinMetrics({ minValue }) {
    return (
        <div className="col-md-4">
            <div className="card border-0 bg-primary">
                <div className="card-body text-white p-2">
                    <span className="small fw-semibold opacity-75 text-uppercase mb-1 me-2">Min</span>
                    <span className="fs-4 fw-bold">
                        {parseInt(minValue)}
                        <span className="fs-6 ms-1">ms</span>
                    </span>
                </div>
            </div>
        </div>
    );
}

function MetricTabs({ metrics, activeIndex, onSelect }) {
    return (
        <div className="border-bottom">
            <ul role="tablist" className="nav nav-tabs border-0 px-2 pt-1">
                {metrics.map((item, i) => (
                    <li key={i} role="presentation" className="nav-item">
                        <button
                            className={`nav-link border-0 position-relative ${i === activeIndex ? 'active' : ''}`}
                            onClick={() => onSelect(i)}
                            type="button"
                            role="tab"
                            style={{
                                color: i === activeIndex ? 'var(--bs-primary)' : 'var(--bs-secondary)',
                                backgroundColor: 'transparent',
                                fontWeight: i === activeIndex ? '600' : '500',
                            }}
                        >
                            <span className="text-uppercase small">{item.label.replace(/_/g, ' ')}</span>
                            {i === activeIndex && (
                                <div
                                    className={`position-absolute bottom-0 start-0 w-100 bg-primary`}
                                    style={{ height: '3px', borderRadius: '3px 3px 0 0' }}
                                />
                            )}
                        </button>
                    </li>
                ))}
            </ul>
        </div>
    );
}

function MetricBar({ label, value, maxValue }) {
    const percentage = Math.min((value / maxValue) * 100, 100);

    return (
        <div className="mb-2">
            <div className="d-flex justify-content-between align-items-center">
                <span className="fw-medium text-muted small">{label}</span>
                <div className="d-flex align-items-center gap-2">
                    <span className="fs-5 fw-bold text-dark">{value.toFixed(0)}</span>
                    <span className="text-muted small">ms</span>
                </div>
            </div>
            <div className="progress">
                <div
                    className="progress-bar"
                    role="progressbar"
                    style={{ width: `${percentage}%` }}
                    aria-valuenow={value}
                    aria-valuemin="0"
                    aria-valuemax={maxValue}
                />
            </div>
        </div>
    );
}

function MetricContent({ item, maxValue }) {
    if (typeof item !== 'object') return null;
    const itemMetrics = Object.entries(item.metrics);

    return (
        <div className="card-body">
            <div className="row g-3">
                <MinMetrics minValue={Math.min(...itemMetrics.map(([_, v]) => v))} />
                <AverageMetrics averageValue={estimateMean(item.metrics)} />
                <MaxMetrics maxValue={Math.max(...itemMetrics.map(([_, v]) => v))} />
            </div>

            <div className="mt-4">
                {itemMetrics
                    .sort(([keyA], [keyB]) => {
                        const numA = parseInt(keyA.replace(/\D/g, ''), 10);
                        const numB = parseInt(keyB.replace(/\D/g, ''), 10);
                        return numA - numB;
                    })
                    .map(([key, value], idx) => (
                        <MetricBar key={idx} label={formatMetricKey(key)} value={value} maxValue={maxValue} />
                    ))}
            </div>
        </div>
    );
}

function Metrics({ token }) {
    const { useState, useEffect } = React;
    const [metrics, setMetrics] = useState([]);
    const [maxValue, setMaxValue] = useState(0);
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        (async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'metrics', type: 'get' });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch metrics');
                if (!json.payload) throw new Error('Payload missing');

                const data = json.payload || [];
                setMetrics(data);

                const allValues = data.flatMap((item) => Object.values(item.metrics));
                const calculatedMax = allValues.length > 0 ? parseInt(Math.max(...allValues)) : 0;
                setMaxValue(calculatedMax);
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
                <div className="d-flex align-items-center gap-2">
                    <h6 className="mb-0 text-white fw-bold">Performance Metrics</h6>
                </div>
                <span className="small text-white opacity-75">Real-time performance monitoring</span>
            </div>

            {metrics.length > 0 && !loading ? (
                <>
                    <MetricTabs metrics={metrics} activeIndex={activeIndex} onSelect={setActiveIndex} />
                    <MetricContent item={activeItem} maxValue={maxValue} />
                </>
            ) : (
                <NoData />
            )}
        </div>
    );
}

window.Metrics = Metrics;
