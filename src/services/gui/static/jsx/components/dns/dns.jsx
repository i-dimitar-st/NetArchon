const { useState, useEffect, useMemo } = React;

function DnsActions({ token }) {
    const [historyCleared, setHistoryCleared] = useState(false);
    const [loading, setLoading] = useState(false);

    const handleClear = async () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;
        try {
            setLoading(true);
            const reqBody = { category: 'dns', type: 'clear', payload: null };
            const res = await fetcher({ token, body: reqBody });
            const jsonRes = await res.json();

            if (!res.ok) throw new Error('Server error');
            if (!jsonRes.success) throw new Error(jsonRes.error || 'Unknown error');

            setHistoryCleared(true);
            console.info('Clearing DNS History');
            setLoading(false);
        } catch {
            console.error('Failed to clear DNS History');
        }
    };
    return (
        <div className="card-body p-0">
            <LoadingOverlay visible={loading} />
            <ActionRow
                label="Clear History"
                onClick={handleClear}
                status={historyCleared ? `Cleared` : 'Not Cleared'}
            />
        </div>
    );
}

function DnsHistory({ token }) {
    const [history, setHistory] = useState([]);
    const [filter, setFilter] = useState('');
    const [sortState, setSortState] = useState({ column: 'query', direction: 'desc' });
    const [loading, setLoading] = useState(true);

    const handleSort = (column) => {
        setSortState((prev) => ({
            column,
            direction: prev.column === column && prev.direction === 'asc' ? 'desc' : 'asc',
        }));
    };

    const filteredAndSorted = useMemo(() => {
        const lowerFilter = filter.toLowerCase();

        return history
            .filter((item) => item.query.toLowerCase().includes(lowerFilter))
            .sort((a, b) => {
                let valA, valB;
                switch (sortState.column) {
                    case 'created':
                        valA = a.created;
                        valB = b.created;
                        break;
                    case 'count':
                        valA = a.query_counter;
                        valB = b.query_counter;
                        break;
                    default:
                        valA = a.query.toLowerCase();
                        valB = b.query.toLowerCase();
                }
                if (valA < valB) return sortState.direction === 'asc' ? -1 : 1;
                if (valA > valB) return sortState.direction === 'asc' ? 1 : -1;
                return 0;
            });
    }, [history, filter, sortState]);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const reqBody = { category: 'dns', type: 'get', resource: 'history' };
                const res = await fetcher({ token, body: reqBody });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch history');
                if (!json?.payload?.history) throw new Error('Payload missing');

                setHistory(json.payload.history);
                console.info('DNS History Fetched');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [token]);

    return (
        <>
            <LoadingOverlay visible={loading} />
            <div className="input-group p-3">
                <input
                    id="dns-history-find-domain"
                    type="text"
                    className="form-control border-top border-bottom rounded-start"
                    placeholder="Find domain..."
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                />
                <button className="btn btn-primary btn-sm rounded-end" onClick={() => setFilter('')}>
                    Clear
                </button>
            </div>

            <div className="table-responsive">
                <table className="table table-sm table-hover align-middle text-nowrap text-center p-0">
                    <thead className="sticky-top">
                        <tr>
                            <th
                                className="small text-muted text-capitalize"
                                onClick={() => handleSort('created')}
                                style={{ cursor: 'pointer' }}
                            >
                                Created
                                {sortState.column === 'created' ? (sortState.direction === 'asc' ? '↑' : '↓') : '↕'}
                            </th>
                            <th
                                className="small text-muted text-capitalize"
                                onClick={() => handleSort('count')}
                                style={{ cursor: 'pointer' }}
                            >
                                Count {sortState.column === 'count' ? (sortState.direction === 'asc' ? '↑' : '↓') : '↕'}
                            </th>
                            <th
                                className="small text-muted text-capitalize"
                                onClick={() => handleSort('query')}
                                style={{ cursor: 'pointer' }}
                            >
                                Domain
                                {sortState.column === 'query' ? (sortState.direction === 'asc' ? '↑' : '↓') : '↕'}
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredAndSorted.map((item, idx) => (
                            <tr key={idx}>
                                <td className="text-center align-middle small">{formatTimestamp(item.created)}</td>
                                <td className="text-center align-middle small">
                                    <span className="badge bg-secondary">{item.query_counter}</span>
                                </td>
                                <td
                                    className="text-center align-middle small text-truncate"
                                    style={{ maxWidth: '200px' }}
                                >
                                    {item.query.toLowerCase()}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    );
}

function DnsStats() {
    const [stats, setStats] = useState({});
    const [loading, setLoading] = useState(true);
    const [maxValue, setMaxValue] = useState(0);

    useEffect(() => {
        const fetchStats = async () => {
            setLoading(true);
            try {
                const reqBody = { category: 'dns', type: 'get', resource: 'stats' };
                const res = await fetcher({ token, body: reqBody });
                const resJson = await res.json();

                if (!resJson.success) throw new Error('Could not fetch stats');
                if (!resJson?.payload?.statistics) throw new Error('Payload missing');

                setStats(resJson.payload.statistics);
                setMaxValue(resJson.payload.statistics.request_total ?? 1);
                console.info('DNS Stats Fetched');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, [token]);

    return (
        <div className="p-3">
            <LoadingOverlay visible={loading} />
            {!loading &&
                Object.entries(stats)
                    .filter(([key, value]) => filterUnnendedStats(value))
                    .filter(([key, value]) => filterUnnendedStats(key))
                    .filter(([key, value]) => !isTimestamp(key))
                    .map(([key, value]) => {
                        const widthPercent = Math.min(parseInt((value / maxValue) * 100), 100);
                        return (
                            <div key={key} className="mb-2">
                                <div className="d-flex justify-content-between align-items-center">
                                    <div className="text-muted text-capitalize small fw-medium">
                                        {formatStatsKey(key)}
                                    </div>
                                    <div>
                                        <span title={value} className="fw-semibold">
                                            {parseInt(value)}
                                        </span>
                                    </div>
                                </div>
                                {maxValue > 0 && (
                                    <div className="progress">
                                        <div
                                            className="progress-bar"
                                            role="progressbar"
                                            style={{ width: `${widthPercent}%` }}
                                            aria-valuenow={parseInt(value)}
                                            aria-valuemin="0"
                                            aria-valuemax={parseInt(maxValue)}
                                        >
                                            {parseInt(widthPercent)}%
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })}
        </div>
    );
}

function Dns({ token }) {
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(false);

    const tabs = [
        { label: 'History', component: <DnsHistory token={token} /> },
        { label: 'Statistics', component: <DnsStats token={token} /> },
        { label: 'Actions', component: <DnsActions token={token} /> },
    ];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title="DNS Service" subtitle="Active Domain Record History" />
            <TabList activeIndex={activeIndex} setActiveIndex={setActiveIndex} tabs={tabs} />
            <TabContent component={tabs[activeIndex].component} />
        </div>
    );
}
