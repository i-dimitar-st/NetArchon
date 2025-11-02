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
            <div className="card rounded-4" style={{ backgroundColor: 'var(--warning-color)' }}>
                <div className="card-body p-2">
                    <span className="text-uppercase fw-semibold text-dark small m-2">Max</span>
                    <span className="fs-4 fw-bold text-dark">
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
            <div className="card rounded-4" style={{ backgroundColor: 'var(--primary-color)' }}>
                <div className="card-body text-white p-2">
                    <span className="small fw-semibold opacity-75 text-uppercase m-2">Average</span>
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
            <div className="card rounded-4" style={{ backgroundColor: 'var(--success-color)' }}>
                <div className="card-body text-white p-2">
                    <span className="small fw-semibold opacity-75 text-uppercase m-2">Min</span>
                    <span className="fs-4 fw-bold">
                        {parseInt(minValue)}
                        <span className="fs-6 ms-1">ms</span>
                    </span>
                </div>
            </div>
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
            <CardHeader title="Performance Metrics" subtitle="Real-time performance monitoring" />
            {metrics && metrics.length > 0 && (
                <>
                    <TabList tabs={metrics} activeIndex={activeIndex} setActiveIndex={setActiveIndex} />
                    <MetricContent item={activeItem} maxValue={maxValue} />
                </>
            )}
        </div>
    );
}
