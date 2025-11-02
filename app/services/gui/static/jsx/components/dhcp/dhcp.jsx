const { useState, useEffect, useMemo } = React;

function getLeasesTypeBadgeClass(type) {
    switch (type) {
        case 'static':
            return 'badge bg-primary';
        case 'manual':
            return 'badge bg-secondary';
        default:
            return 'badge bg-success';
    }
}

function DhcpLeases({ token }) {
    const [leases, setLeases] = useState([]);
    const [tableHeaderNames, setTableHeaderNames] = useState([]);
    const [sortState, setSortState] = useState({ column: '', direction: 'asc' });
    const [loading, setLoading] = useState(true);

    const handleSort = (column) => {
        setSortState((prev) => ({
            column,
            direction: prev.column === column && prev.direction === 'asc' ? 'desc' : 'asc',
        }));
    };

    useEffect(() => {
        const fetchLeases = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'dhcp_leases', type: 'get' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch DHCP leases');
                setLeases(payload || []);
                setTableHeaderNames(['type', 'ip', 'mac', 'hostname', 'timestamp', 'expiry_time']);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchLeases();
    }, [token]);

    const sortedLeases = useMemo(() => {
        if (!sortState.column) return leases;
        return [...leases].sort((a, b) => {
            let valA = a[sortState.column] ?? '';
            let valB = b[sortState.column] ?? '';

            if (sortState.column.toLowerCase() === 'ip') {
                const sumIpContent = (ip) => ip.split('.').reduce((sum, value) => sum + parseInt(value, 10), 0);
                valA = sumIpContent(valA);
                valB = sumIpContent(valB);
            } else {
                if (typeof valA === 'string') valA = valA.toLowerCase();
                if (typeof valB === 'string') valB = valB.toLowerCase();
            }

            if (valA < valB) return sortState.direction === 'asc' ? -1 : 1;
            if (valA > valB) return sortState.direction === 'asc' ? 1 : -1;
            return 0;
        });
    }, [leases, sortState]);

    return (
        <div className="card-body p-0">
            <LoadingOverlay visible={loading} />
            <div className="table-responsive">
                <table className="table table-sm table-hover align-middle text-nowrap text-center p-0">
                    <thead className="table-light sticky-top">
                        <tr>
                            {tableHeaderNames.map((headerName) => (
                                <th
                                    key={headerName}
                                    onClick={() => handleSort(headerName)}
                                    style={{ cursor: 'pointer' }}
                                    className="small text-muted text-capitalize"
                                >
                                    {headerName.replaceAll('_', ' ')}
                                    {sortState.column === headerName
                                        ? sortState.direction === 'asc'
                                            ? ' ↑'
                                            : ' ↓'
                                        : ' ↕'}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {sortedLeases.map((lease, idx) => (
                            <tr key={idx}>
                                {tableHeaderNames.map((key) => {
                                    let value = lease[key] ?? '';
                                    if (key === 'type')
                                        value = <span className={getLeasesTypeBadgeClass(value)}>{value}</span>;
                                    else if (key.includes('time')) value = formatTimestamp(value);

                                    return (
                                        <td className="small" key={key}>
                                            {value}
                                        </td>
                                    );
                                })}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function DhcpStats({ token }) {
    const [stats, setStats] = useState({});
    const [loading, setLoading] = useState(true);
    const [maxValue, setMaxValue] = useState(0);

    useEffect(() => {
        const fetchStats = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'dhcp_leases', type: 'get-stats' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch DHCP stats');
                setStats(payload || {});
                setMaxValue(payload.received_total ?? 1);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, [token]);

    return (
        <div className="card-body p-3">
            <LoadingOverlay visible={loading} />
            {!loading &&
                Object.entries(stats)
                    .filter(([key, value]) => filterUnnendedStats(value))
                    .filter(([key, value]) => !isTimestamp(key))
                    .map(([key, value]) => {
                        const widthPercent = Math.min((value / maxValue) * 100, 100) + '%';
                        return (
                            <div key={key} className="mb-2">
                                <div className="d-flex justify-content-between align-items-center">
                                    <div className="text-muted text-capitalize small fw-medium">
                                        {formatStatsKey(key)}
                                    </div>
                                    <div>
                                        <span title={value} className="fw-semibold small">
                                            {isTimestamp(key)
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
    );
}

function Dhcp({ token }) {
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(false);

    const tabs = [
        { label: 'Leases', component: <DhcpLeases token={token} /> },
        { label: 'Statistics', component: <DhcpStats token={token} /> },
    ];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title="DHCP Service" subtitle="Dynamic Lease Serice" />
            <TabList activeIndex={activeIndex} setActiveIndex={setActiveIndex} tabs={tabs} />
            <TabContent component={tabs[activeIndex].component} />
        </div>
    );
}
