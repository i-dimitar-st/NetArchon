function getBadgeClass(type) {
    switch (type) {
        case 'static':
            return 'badge-dhcp-static';
        case 'manual':
            return 'badge-dhcp-manual';
        default:
            return 'badge-dhcp-dynamic';
    }
}

function DhcpLeases({ token }) {
    const { useState, useEffect, useMemo } = React;
    const [leases, setLeases] = useState([]);
    const [sortState, setSortState] = useState({ column: 'mac', direction: 'asc' });
    const [loading, setLoading] = useState(true);

    const handleSort = (column) => {
        setSortState((prev) => ({
            column,
            direction: prev.column === column && prev.direction === 'asc' ? 'desc' : 'asc',
        }));
    };

    const sortedLeases = useMemo(() => {
        return [...leases].sort((a, b) => {
            let valA = a[sortState.column] || '';
            let valB = b[sortState.column] || '';

            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            if (valA < valB) return sortState.direction === 'asc' ? -1 : 1;
            if (valA > valB) return sortState.direction === 'asc' ? 1 : -1;
            return 0;
        });
    }, [leases, sortState]);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'dhcp-leases', type: 'get' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch DHCP leases');
                setLeases(payload || []);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token]);

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex justify-content-between align-items-center">
                <h6 className="mb-0 fw-bold text-capitalize">
                    Leases
                    <span className="badge bg-primary ms-2">{leases.length}</span>
                </h6>
                <span>📋</span>
            </div>

            <div className="card-body p-0">
                <div className="table-responsive h-100">
                    <table className="table table-sm table-hover align-middle text-nowrap text-center mb-0">
                        <thead>
                            <tr>
                                {['mac', 'ip', 'hostname', 'type', 'lease_start', 'lease_expiry'].map((key, idx) => {
                                    const headerNames = {
                                        mac: 'MAC',
                                        ip: 'IP',
                                        hostname: 'Hostname',
                                        type: 'Type',
                                        lease_start: 'Leased',
                                        lease_expiry: 'Expiry',
                                    };
                                    return (
                                        <th
                                            key={idx}
                                            onClick={() => handleSort(key)}
                                            style={{ cursor: 'pointer', color: 'var(--text-secondary)' }}
                                        >
                                            {headerNames[key]}{' '}
                                            {sortState.column === key
                                                ? sortState.direction === 'asc'
                                                    ? '▲'
                                                    : '▼'
                                                : '↕'}
                                        </th>
                                    );
                                })}
                            </tr>
                        </thead>
                        <tbody>
                            {sortedLeases.map((lease, idx) => (
                                <tr key={idx}>
                                    <td className="px-2">{lease.mac}</td>
                                    <td className="px-2">{lease.ip}</td>
                                    <td className="px-2">{lease.hostname || ''}</td>
                                    <td className="px-2">
                                        <span className={`badge ${getBadgeClass(lease.type)}`}>
                                            {lease.type || 'manual'}
                                        </span>
                                    </td>
                                    <td className="px-2">{formatTimestamp(lease.timestamp)}</td>
                                    <td className="px-2">{formatTimestamp(lease.expiry_time)}</td>
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
