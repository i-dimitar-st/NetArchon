const { useState, useEffect } = React;

function getUnitFromLabel(label = '') {
    label = label.toLowerCase();

    if (label.includes('frequency')) return 'Hz';
    if (label.includes('temperature') || label.includes('coretemp')) return '°C';
    if (label.includes('memory') || label.includes('rss')) return 'MB';
    if (label.includes('cpu')) return '%';
    if (label.includes('load avg.core')) return '%';
    if (label.includes('uptime')) return 'sec';
    if (label.includes('disk') || label.includes('free') || label.includes('used')) return 'GB';
    if (label.includes('packets') || label.includes('errors')) return 'qty';
    return '';
}

function getStatsFromActiveTabName({ activeTabName, data }) {
    let stats;
    switch (activeTabName) {
        case 'cpu':
            stats = getCpuStats(data);
            break;
        case 'disks':
            stats = getDisksStats(data);
            break;
        case 'temperature':
            stats = getTempStats(data);
            break;
        case 'memory':
            stats = getMemoryStats(data);
            break;
        case 'network':
            stats = getNetworkStats(data);
            break;
        case 'process':
            stats = getProcessStats(data);
            break;
        case 'system':
            stats = getSystemStats(data);
            break;
        default:
            stats = {
                min: { label: 'Min', value: 0, unit: '' },
                avg: { label: 'Average', value: 0, unit: '' },
                max: { label: 'Max', value: 0, unit: '' },
            };
    }
    return stats;
}

function getCpuStats(data) {
    const minVal = data.overall.value;
    const maxVal = data.cores.value;
    const avgVal = '';
    return {
        min: { label: 'Overall', value: minVal, unit: data.overall.unit },
        avg: { label: 'Overall', value: avgVal, unit: '' },
        max: { label: 'Cores', value: maxVal, unit: 'qty' },
    };
}

function getDisksStats(data) {
    const disks = Object.values(data);
    const totalFree = disks.reduce((acc, i) => acc + i.free.value, 0);
    const totalUsed = disks.reduce((acc, i) => acc + i.used.value, 0);
    const totalTotal = disks.reduce((acc, i) => acc + i.total.value, 0);
    return {
        min: { label: 'Free', value: totalFree, unit: 'GB' },
        avg: { label: 'Used', value: totalUsed, unit: 'GB' },
        max: { label: 'Total', value: totalTotal, unit: 'GB' },
    };
}

function getTempStats(data) {
    const values = Object.values(flattenStats(data));
    const minVal = parseInt(Math.min(...values));
    const maxVal = parseInt(Math.max(...values));
    const avgVal = parseInt(values.reduce((sum, val) => sum + val, 0) / values.length);
    return {
        min: { label: 'Min', value: minVal, unit: '°C' },
        avg: { label: 'Overall', value: avgVal, unit: '°C' },
        max: { label: 'Max', value: maxVal, unit: '°C' },
    };
}

function getMemoryStats(data) {
    return {
        min: { label: 'Free', value: parseInt((100 * data.available.value) / data.total.value), unit: '%' },
        avg: { label: 'Used', value: data.used.value, unit: '%' },
        max: { label: 'Total', value: data.total.value, unit: '%' },
    };
}

function getNetworkStats(data) {
    const interfaces = Object.values(data);
    const totalTraffic = interfaces.reduce((acc, i) => acc + i.data_recv.value + i.data_sent.value, 0);
    const totalPackets = interfaces.reduce((acc, i) => acc + i.packets_recv.value + i.packets_sent.value, 0);
    const totalErrors = interfaces.reduce((acc, i) => acc + i.errors_recv.value + i.errors_sent.value, 0);

    return {
        min: { label: 'Data Rx+Tx', value: totalTraffic, unit: 'MB' },
        avg: { label: 'Packets', value: totalPackets, unit: 'qty' },
        max: { label: 'Errors', value: totalErrors, unit: 'qty' },
    };
}

function getProcessStats(data) {
    return {
        min: { label: 'CPU', value: data.cpu.value, unit: '%' },
        avg: { label: 'Memory RSS', value: data.memory_rss.value, unit: 'MB' },
        max: { label: 'Uptime', value: data.uptime.value, unit: 'sec' },
    };
}

function getSystemStats(data) {
    return {
        min: { label: 'Architecture', value: data.architecture.value, unit: '' },
        avg: { label: 'OS', value: data.os_version.value, unit: '' },
        max: { label: 'Uptime', value: data.uptime.value, unit: 'days' },
    };
}

function StatCard({ label, value, unit = '' }) {
    return (
        <div className="col-md-4">
            <div className="card rounded-4" style={{ backgroundColor: 'var(--primary-color)' }}>
                <div className="card-body text-white p-2">
                    <span className="small fw-semibold opacity-75 text-uppercase m-2">{label}</span>
                    <span className="fs-4 fw-bold">
                        {value}
                        {unit && <span className="fs-6 ms-1">{unit}</span>}
                    </span>
                </div>
            </div>
        </div>
    );
}

function StatBar({ label, value, maxValue }) {
    const percentage = maxValue > 0 ? parseInt(Math.min((value / maxValue) * 100, 100)) : 0;
    return (
        <div className="mb-2">
            <div className="d-flex justify-content-between align-items-center">
                <span className="fw-medium text-muted small">{label}</span>
                <div className="d-flex align-items-center gap-2">
                    <span className="fs-5 fw-bold text-dark">{value}</span>
                    <span className="text-muted small">{getUnitFromLabel(label)}</span>
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

function flattenStats(obj, prefix = '') {
    const result = {};

    for (const [key, val] of Object.entries(obj)) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        if (val && typeof val === 'object') {
            if ('value' in val) {
                result[newKey] = val.value;
            } else {
                Object.assign(result, flattenStats(val, newKey));
            }
        } else {
            result[newKey] = val;
        }
    }

    return result;
}

function ActiveContent({ data, activeTabName }) {
    if (!data) return <NoData />;
    const flat = flattenStats(data);
    const stats = getStatsFromActiveTabName({ activeTabName, data });
    return (
        <div className="card-body">
            <div className="row g-2 my-2">
                <StatCard label={stats.min.label} value={stats.min.value} unit={stats.min.unit} />
                <StatCard label={stats.avg.label} value={stats.avg.value} unit={stats.avg.unit} />
                <StatCard label={stats.max.label} value={stats.max.value} unit={stats.max.unit} />
            </div>
            <div>
                {Object.entries(flat).map(([key, value], idx) => (
                    <StatBar key={idx} label={key.replaceAll('_', ' ')} value={value} maxValue={stats.max.value} />
                ))}
            </div>
        </div>
    );
}

function ActiveTabsButton({ tabKey, index, activeIndex, setActiveIndex }) {
    const isActive = index === activeIndex;
    const activeState = isActive ? 'active' : '';
    const activeColor = isActive ? 'var(--bs-primary)' : 'var(--bs-secondary)';
    const activeFontWeight = isActive ? '600' : '500';
    return (
        <button
            className={`nav-link border-0 position-relative ${activeState}`}
            onClick={() => setActiveIndex(index)}
            type="button"
            role="tab"
            style={{
                color: activeColor,
                backgroundColor: 'transparent',
                fontWeight: activeFontWeight,
            }}
        >
            <span className="text-uppercase small">{tabKey.replaceAll('_', ' ')}</span>
            {isActive && (
                <div
                    className={`position-absolute bottom-0 start-0 w-100 bg-primary`}
                    style={{ height: '3px', borderRadius: '3px 3px 0 0' }}
                />
            )}
        </button>
    );
}

function ActiveTabs({ keys, activeIndex, setActiveIndex }) {
    if (!keys.length) return null;
    return (
        <div>
            <ul role="tablist" className="nav nav-tabs">
                {keys.map((tabKey, index) => (
                    <li key={tabKey} role="presentation" className="nav-item">
                        <ActiveTabsButton
                            tabKey={tabKey}
                            index={index}
                            activeIndex={activeIndex}
                            setActiveIndex={setActiveIndex}
                        />
                    </li>
                ))}
            </ul>
        </div>
    );
}

function Info({ token }) {
    const [loading, setLoading] = useState(true);
    const [activeIndex, setActiveIndex] = useState(0);
    const [data, setData] = useState({});
    const keys = Object.keys(data);

    useEffect(() => {
        const fetchSystemStats = async () => {
            setLoading(true);
            try {
                const reqBody = { category: 'info', type: 'get', resource: 'system' };
                const res = await fetcher({ token, body: reqBody });
                const json = await res.json();

                if (!json.success) throw new Error('Failed to fetch system stats');
                if (!json?.payload?.info) throw new Error('Response missing Payload');

                setData(json.payload.info);
                console.info('System Info Fetched');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchSystemStats();
    }, [token]);

    const activeTabName = keys[activeIndex];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title="System Info" subtitle="Detailed System Information" />
            {keys && keys.length > 0 && (
                <>
                    <ActiveTabs keys={keys} activeIndex={activeIndex} setActiveIndex={setActiveIndex} />
                    <ActiveContent data={data[keys[activeIndex]]} activeTabName={activeTabName} />
                </>
            )}
        </div>
    );
}
