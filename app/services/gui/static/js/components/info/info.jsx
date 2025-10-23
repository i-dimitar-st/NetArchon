function StatsCard({ title, data, loading }) {
    const renderEntries = (obj, depth = 0) => {
        return Object.entries(obj).map(([key, value]) => {
            const isObject = typeof value === 'object' && value !== null;
            if (isObject && 'value' in value) {
                return (
                    <div key={key} className={`ms-${depth}`}>
                        <div className="d-flex justify-content-between align-items-start">
                            <div className="text-muted text-uppercase small">{key.replaceAll('_', ' ')}</div>
                            <div className="small text-end fw-bold">
                                {value.value} {value.unit ?? ''}
                            </div>
                        </div>
                    </div>
                );
            }

            return (
                <div key={key} className={`ms-${depth}`}>
                    <div className="text-muted text-uppercase small">{key.replaceAll('_', ' ')}</div>
                    {isObject ? (
                        renderEntries(value, depth + 2)
                    ) : (
                        <div className="small text-end fw-bold">{String(value)}</div>
                    )}
                </div>
            );
        });
    };

    return (
        <div className="col-12 col-md-6 col-lg-3">
            <div className="card">
                <LoadingOverlay visible={loading} />
                <h6 className="card-header fw-bold text-uppercase">{title.replace(/_/g, ' ')}</h6>
                <div className="card-body p-3">
                    {Object.keys(data).length ? renderEntries(data) : <div className="text-muted small">No data</div>}
                </div>
            </div>
        </div>
    );
}

function SystemStats({ token }) {
    const { useState, useEffect } = React;
    const [data, setData] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchStats = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, category: 'stats', type: 'get-system' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch system stats');
                setData(payload || {});
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, [token]);

    if (!data || typeof data !== 'object') return null;

    return (
        <>
            {Object.entries(data).map(([key, value]) => (
                <StatsCard key={key} title={key} data={value} loading={loading} />
            ))}
        </>
    );
}
function NetworkInterfacesTable({ token }) {
    const { useState, useEffect } = React;
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchNetwork = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get-network-interfaces' });
                const json = await res.json();
                if (!json.success) throw new Error('Could not fetch network interfaces');
                setData(json.payload || []);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchNetwork();
    }, [token]);

    return (
        <div className="col-12">
            <div className="card">
                <LoadingOverlay visible={loading} />
                <div className="card-header bg-white d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold text-capitalize" style={{ color: 'var(--text-secondary)' }}>
                        Network Interfaces
                    </h5>
                </div>
                <div className="card-body p-0">
                    <div className="table-responsive">
                        <table className="table table-sm table-hover align-middle text-nowrap text-center">
                            <thead className="table-light">
                                <tr>
                                    <th>Interface</th>
                                    <th>Type</th>
                                    <th>IP</th>
                                    <th>Netmask</th>
                                    <th>Broadcast</th>
                                    <th>MAC</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.map((iface, idx) => (
                                    <tr key={idx}>
                                        <td>{iface.name}</td>
                                        <td>{iface.type || 'N/A'}</td>
                                        <td>{iface.ip_address || 'N/A'}</td>
                                        <td>{iface.netmask || 'N/A'}</td>
                                        <td>{iface.broadcast || 'N/A'}</td>
                                        <td>{(iface.mac_address || 'N/A').toUpperCase()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}

function Info({ token }) {
    return (
        <div className="row g-4">
            <SystemStats token={token} />
            <NetworkInterfacesTable token={token} />
        </div>
    );
}

window.SystemStats = SystemStats;
window.Info = Info;
