function DnsHistory({ token }) {
    const { useState, useEffect, useMemo } = React;
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
                const res = await fetcher({ token, category: 'dns-history', type: 'get' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch data');
                setHistory(payload || []);
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
        <div className="card flex-fill d-flex flex-column">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <h6>
                    History <span className="badge bg-secondary ms-2">{history.length}</span>
                </h6>
            </div>

            <div className="card-body d-flex flex-column p-0">
                <div className="input-group py-4 px-0">
                    <input
                        type="text"
                        className="form-control border-0 border-top border-bottom rounded-0"
                        placeholder="Find domain..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                    />
                    <button className="btn btn-primary btn-sm rounded-0" onClick={() => setFilter('')}>
                        Clear
                    </button>
                </div>

                <div className="table-responsive">
                    <table className="table table-sm table-hover align-middle text-nowrap mb-0">
                        <thead className="table-light">
                            <tr>
                                <th
                                    className="text-center small text-muted text-capitalize"
                                    onClick={() => handleSort('created')}
                                    style={{ cursor: 'pointer' }}
                                >
                                    Created
                                    {sortState.column === 'created' ? (sortState.direction === 'asc' ? '↑' : '↓') : '↕'}
                                </th>
                                <th
                                    className="text-center small text-muted text-capitalize"
                                    onClick={() => handleSort('count')}
                                    style={{ cursor: 'pointer' }}
                                >
                                    Count{' '}
                                    {sortState.column === 'count' ? (sortState.direction === 'asc' ? '↑' : '↓') : '↕'}
                                </th>
                                <th
                                    className="text-center small text-muted text-capitalize"
                                    onClick={() => handleSort('query')}
                                    style={{ cursor: 'pointer' }}
                                >
                                    Domain{' '}
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
            </div>
        </div>
    );
}

window.DnsHistory = DnsHistory;
