function estimateMean(metrics) {
    const keys = Object.keys(metrics)
        .filter((k) => k.startsWith('p'))
        .sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));

    if (!keys.length) return null;

    let mean = 0;
    const n = keys.length;

    for (let i = 0; i < n; i++) {
        const weight = i === 0 ? 0.5 / n : 1 / n;
        const value = i === 0 ? metrics[keys[i]] : (metrics[keys[i - 1]] + metrics[keys[i]]) / 2;
        mean += weight * value;
    }

    return mean;
}

function MaxMetrics({ maxValue }) {
    return (
        <div className="col-md-4">
            <div className="card rounded-4" style={{ backgroundColor: 'var(--warning-color)' }}>
                <div className="card-body p-2">
                    <span className="text-uppercase fw-semibold opacity-75 text-dark small m-2">Max</span>
                    <span className="fs-4 fw-bold text-dark">
                        {maxValue.toFixed(2)}
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
                        {averageValue.toFixed(2)}
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
                        {minValue.toFixed(2)}
                        <span className="fs-6 ms-1">ms</span>
                    </span>
                </div>
            </div>
        </div>
    );
}

function MetricBar({ label, value, maxValue }) {
    const percentage = parseInt(Math.min((value / maxValue) * 100, 100));

    return (
        <div className="mb-2">
            <div className="d-flex justify-content-between align-items-center">
                <span className="fw-medium text-muted small">{label}</span>
                <div className="d-flex align-items-center gap-2">
                    <span className="fs-5 fw-bold text-dark">{value.toFixed(2)}</span>
                    <span className="text-muted small">ms</span>
                </div>
            </div>
            <div className="progress">
                <div
                    className="progress-bar"
                    role="progressbar"
                    style={{ width: `${percentage}%` }}
                    aria-valuenow={percentage}
                    aria-valuemin="0"
                    aria-valuemax={maxValue}
                >
                    {percentage}%
                </div>
            </div>
        </div>
    );
}

function MetricContent({ item, maxValueForVisualiation }) {
    const itemMetrics = Object.entries(item.metrics);
    const minValue = parseFloat(Math.min(...itemMetrics.map(([_, v]) => v)));
    const avgValue = parseFloat(estimateMean(item.metrics));
    const maxValue = parseFloat(Math.max(...itemMetrics.map(([_, v]) => v)));

    return (
        <div className="card-body">
            <div className="row g-3">
                <MinMetrics minValue={minValue} />
                <AverageMetrics averageValue={avgValue} />
                <MaxMetrics maxValue={maxValue} />
            </div>

            <div className="mt-4">
                {itemMetrics
                    .sort(([keyA], [keyB]) => {
                        const numA = parseInt(keyA.replace(/\D/g, ''), 10);
                        const numB = parseInt(keyB.replace(/\D/g, ''), 10);
                        return numA - numB;
                    })
                    .map(([key, value], idx) => (
                        <MetricBar
                            key={idx}
                            label={formatMetricKey(key)}
                            value={value}
                            maxValue={maxValueForVisualiation}
                        />
                    ))}
            </div>
        </div>
    );
}

function Metrics({ token }) {
    const { useState, useEffect } = React;
    const [metrics, setMetrics] = useState([]);
    const [activeIndex, setActiveIndex] = useState(0);
    const [maxValueForVisualiation, setMaxValueForVisualiation] = useState(15000);
    const [loading, setLoading] = useState(true);

    const transformMetricValues = (metricReceived) =>
        metricReceived.map((item) => ({
            ...item,
            metrics: Object.fromEntries(Object.entries(item.metrics).map(([key, value]) => [key, value])),
        }));

    useEffect(() => {
        const getMetrics = async () => {
            setLoading(true);
            try {
                const reqBody = { category: 'metrics', type: 'get' };
                const res = await fetcher({ token, body: reqBody });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch metrics');
                if (!json?.payload?.metrics) throw new Error('Metrics missing');

                setMetrics(transformMetricValues(json.payload.metrics));
                console.info('Metrics fetched');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        getMetrics();
    }, [token]);

    const activeItem = metrics[activeIndex];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title="Performance Metrics" subtitle="Real-time performance monitoring" />
            {metrics && metrics.length > 0 && (
                <>
                    <TabList tabs={metrics} activeIndex={activeIndex} setActiveIndex={setActiveIndex} />
                    <MetricContent item={activeItem} maxValueForVisualiation={maxValueForVisualiation} />
                </>
            )}
        </div>
    );
}
