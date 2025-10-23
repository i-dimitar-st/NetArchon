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
    const { useState, useEffect, useMemo } = React;
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
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <h6>
                    Leases
                    <span className="badge bg-secondary ms-2">{leases.length}</span>
                </h6>
            </div>

            <div className="card-body p-0">
                <div className="table-responsive">
                    <table className="table table-sm table-hover align-middle text-nowrap text-center p-0">
                        <thead className="table-light">
                            <tr>
                                {tableHeaderNames.map((headerName) => (
                                    <th
                                        key={headerName}
                                        onClick={() => handleSort(headerName)}
                                        style={{ cursor: 'pointer' }}
                                        className="small text-muted text-capitalize"
                                    >
                                        {headerName.toLowerCase().replaceAll('_', ' ')}{' '}
                                        {sortState.column === headerName
                                            ? sortState.direction === 'asc'
                                                ? '↑'
                                                : '↓'
                                            : '↕'}
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
        </div>
    );
}

window.DhcpLeases = DhcpLeases;
