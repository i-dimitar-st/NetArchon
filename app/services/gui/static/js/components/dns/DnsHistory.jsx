function DnsHistory({ token }) {
    const { useState, useEffect, useMemo } = React;
    const [history, setHistory] = useState([]);
    const [filter, setFilter] = useState('');
    const [sortState, setSortState] = useState({ column: 'query', direction: 'desc' });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

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
                const res = await fetcher({ token, category: 'dns-history', type: 'get' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch data');
                setHistory(payload || []);
                setError(null);
            } catch (err) {
                console.error(err);
                setError('Failed to load DNS history');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [token]);

    return (
        <div className="card flex-fill d-flex flex-column">
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex justify-content-between align-items-center">
                <h6 className="mb-0 fw-bold text-capitalize">
                    History <span className="badge bg-primary ms-2">{history.length}</span>
                </h6>
            </div>

            <div className="card-body d-flex flex-column p-3">
                <div className="input-group mb-3">
                    <span className="input-group-text">🔍</span>
                    <input
                        type="text"
                        className="form-control"
                        placeholder="Find domain..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                    />
                    <button className="btn btn-outline-secondary" onClick={() => setFilter('')}>
                        ✖
                    </button>
                </div>

                {error ? (
                    <div className="alert alert-danger small py-2 mb-0">{error}</div>
                ) : (
                    <div className="table-responsive flex-fill">
                        <table className="table table-sm table-hover align-middle text-nowrap mb-0">
                            <thead className="table-light">
                                <tr>
                                    <th onClick={() => handleSort('created')} style={{ cursor: 'pointer' }}>
                                        Created{' '}
                                        {sortState.column === 'created'
                                            ? sortState.direction === 'asc'
                                                ? '▲'
                                                : '▼'
                                            : '↕'}
                                    </th>
                                    <th onClick={() => handleSort('count')} style={{ cursor: 'pointer' }}>
                                        Count{' '}
                                        {sortState.column === 'count'
                                            ? sortState.direction === 'asc'
                                                ? '▲'
                                                : '▼'
                                            : '↕'}
                                    </th>
                                    <th onClick={() => handleSort('query')} style={{ cursor: 'pointer' }}>
                                        Domain{' '}
                                        {sortState.column === 'query'
                                            ? sortState.direction === 'asc'
                                                ? '▲'
                                                : '▼'
                                            : '↕'}
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredAndSorted.map((item, idx) => (
                                    <tr key={idx}>
                                        <td>{formatTimestamp(item.created)}</td>
                                        <td className="text-center">
                                            <span className="badge bg-primary">{item.query_counter}</span>
                                        </td>
                                        <td>{item.query.toLowerCase()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}

window.DnsHistory = DnsHistory;
