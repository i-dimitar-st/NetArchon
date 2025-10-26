const { useState, useEffect, useRef, useMemo } = React;

function DnsHistoryLegend() {
    return (
        <div className="col-12 mt-2">
            <div className="p-3 bg-light rounded">
                <div className="d-flex flex-wrap gap-3 align-items-center">
                    <span className="fw-bold text-muted small">Legend:</span>
                    <span className="badge bg-danger opacity-75">Blacklisted</span>
                    <span className="badge bg-success opacity-75">Whitelisted</span>
                    <span>
                        <span className="badge bg-danger me-1">High</span>
                        <small className="text-muted">Score &gt; 0.9</small>
                    </span>
                    <span>
                        <span className="badge bg-warning text-dark me-1">Medium</span>
                        <small className="text-muted">0.25-0.9</small>
                    </span>
                    <span>
                        <span className="badge bg-success me-1">Low</span>
                        <small className="text-muted">&lt; 0.25</small>
                    </span>
                </div>
            </div>
        </div>
    );
}

function DnsHistorySummary({ displayedHistory }) {
    return (
        <div className="d-flex gap-1 align-items-center justify-content-md-end h-100">
            <span className="badge bg-primary fs-6 py-2 px-3">Total: {displayedHistory.length}</span>
            <span className="badge bg-danger fs-6 py-2 px-3">
                High: {displayedHistory.filter((item) => item.prediction > 0.9).length}
            </span>
            <span className="badge bg-warning text-dark fs-6 py-2 px-3">
                Medium:
                {displayedHistory.filter((item) => item.prediction >= 0.25 && item.prediction <= 0.9).length}
            </span>
            <span className="badge bg-success fs-6 py-2 px-3">
                Low: {displayedHistory.filter((item) => item.prediction < 0.25).length}
            </span>
        </div>
    );
}

function NeuralNetTabs({ tabs, activeTab, onSelect }) {
    return (
        <div className="border-bottom">
            <ul role="tablist" className="nav nav-tabs border-0 px-3 pt-2">
                {tabs.map((tab) => (
                    <li key={tab.id} role="presentation" className="nav-item">
                        <button
                            className={`nav-link border-0 position-relative ${activeTab === tab.id ? 'active' : ''}`}
                            onClick={() => onSelect(tab.id)}
                            type="button"
                            role="tab"
                            style={{
                                color: activeTab === tab.id ? 'var(--bs-primary)' : 'var(--bs-secondary)',
                                backgroundColor: 'transparent',
                                fontWeight: activeTab === tab.id ? '600' : '500',
                            }}
                        >
                            <span className="text-uppercase small">{tab.label}</span>
                            {activeTab === tab.id && (
                                <div
                                    className="position-absolute bottom-0 start-0 w-100 bg-primary"
                                    style={{ height: '3px', borderRadius: '3px 3px 0 0' }}
                                />
                            )}
                        </button>
                    </li>
                ))}
            </ul>
        </div>
    );
}

function NeuralNetTabContent({
    activeTab,
    token,
    blacklists,
    setBlacklists,
    whitelists,
    setWhitelists,
    predictions,
    setPredictions,
}) {
    switch (activeTab) {
        case 'actions':
            return (
                <ActionsTab token={token} dnsHistory={[]} predictions={predictions} setPredictions={setPredictions} />
            );
        case 'history':
            return <HistoryTab token={token} predictions={predictions} />;
        case 'blacklist':
            return <BlacklistTab token={token} blacklists={blacklists} setBlacklists={setBlacklists} />;
        case 'whitelist':
            return <WhitelistTab token={token} whitelists={whitelists} setWhitelists={setWhitelists} />;
        default:
            return null;
    }
}

// -------------------- Actions --------------------

const ActionRow = ({ label, onClick, status }) => (
    <div className="d-flex justify-content-between align-items-center px-4 py-2 border-bottom">
        <button className="btn btn-primary btn-sm" onClick={onClick} style={{ minWidth: '150px' }}>
            {label}
        </button>
        <span className="badge bg-secondary" style={{ minWidth: '120px', textAlign: 'center' }}>
            {status}
        </span>
    </div>
);

function ActionsTab({ token, dnsHistory, predictions, setPredictions, setBlacklists, setWhitelists }) {
    const [trainingStatus, setTrainingStatus] = useState('Idle');
    const [historyCleared, setHistoryCleared] = useState(false);
    const [lastUpdated, setLastUpdated] = useState('');

    const [domain, setDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [modalType, setModalType] = useState('blacklist');
    const [loading, setLoading] = useState(false);

    // ---------------- Handlers ----------------
    const handleTrainModel = async () => {
        setTrainingStatus('Starting...');
        try {
            const res = await fetcher({ token, category: 'neural-net', type: 'train-new-model', timeout: 600_000 });
            if (!res.ok) throw new Error('Failed to start training');

            const reader = res.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop();

                lines.forEach((line) => {
                    if (!line.trim()) return;
                    try {
                        const json = JSON.parse(line);
                        const payload = json.payload || {};
                        let extra = '';
                        if (payload.payload) {
                            const p = payload.payload;
                            if (p.avg_loss !== undefined) extra += ` Loss:${p.avg_loss.toFixed(3)}`;
                            if (p.accuracy !== undefined) extra += ` Acc:${p.accuracy.toFixed(3)}`;
                            if (p.training_time !== undefined) extra += ` Time:${p.training_time.toFixed(2)}s`;
                        }
                        const status = payload.status || json.status || 'Training';
                        const progress = payload.progress !== undefined ? (payload.progress * 100).toFixed(1) : null;
                        setTrainingStatus(`${status}${progress ? ` ${progress}%` : ''}${extra}`);
                    } catch (e) {
                        console.error(e);
                    }
                });
            }
            setTrainingStatus('Training Complete');
        } catch (err) {
            console.error(err);
            setTrainingStatus('Training Failed');
        }
    };

    const handlePredict = async () => {
        setPredictions(['Predicting...']);
        try {
            const res = await fetcher({
                token,
                category: 'neural-net',
                type: 'predict',
                payload: dnsHistory.map((item) => item.query),
            });
            const json = await res.json();

            if (!json.success) throw new Error('Could not fetch predictions');
            if (!json.payload) throw new Error('Payload missing');

            const data = json.payload.predictions;
            setPredictions(data);
        } catch (err) {
            console.error(err);
            setPredictions([]);
        }
    };

    const handleClear = async () => {
        if (!confirm('Clear DNS history?')) return;
        try {
            const res = await fetcher({ token, category: 'dns-history', type: 'clear' });
            if (!res.ok) throw new Error('Server error');
            const data = await res.json();
            if (!data.success) throw new Error('Failed to clear history');
            setHistoryCleared(true);
        } catch (err) {
            console.error(err);
        }
    };

    const handleFetchTimestamp = async () => {
        try {
            const res = await fetcher({ token, category: 'neural-net', type: 'get-model-age' });
            if (!res.ok) throw new Error('Server error');
            const data = await res.json();
            if (data?.payload?.timestamp) setLastUpdated(data.payload.timestamp);
        } catch (err) {
            console.error(err);
        }
    };

    const handleAddDomain = async (d) => {
        setLoading(true);
        try {
            if (modalType === 'blacklist') {
                await fetcher({ token, category: 'blacklist', type: 'add', payload: d });
                setBlacklists((prev) => [...prev, d]);
            } else {
                await fetcher({ token, category: 'whitelist', type: 'add', payload: d });
                setWhitelists((prev) => [...prev, d]);
            }
            setDomain('');
            setShowModal(false);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    // ---------------- JSX ----------------
    return (
        <div className="p-0">
            <ActionRow label="Train Model" onClick={handleTrainModel} status={trainingStatus} />
            <ActionRow
                label="Last Trained"
                onClick={handleFetchTimestamp}
                status={lastUpdated ? `${Math.floor(lastUpdated / 60)} min ago` : 'Not used yet'}
            />
            <ActionRow
                label="Rate History"
                onClick={handlePredict}
                status={Array.isArray(predictions) ? `${predictions.length} Predictions` : 'Not used yet'}
            />
            <ActionRow
                label="Clear History"
                onClick={handleClear}
                status={historyCleared ? 'Cleared' : 'Not Cleared'}
            />
            <ActionRow
                label="Add to Blacklist"
                onClick={() => {
                    setModalType('blacklist');
                    setShowModal(true);
                }}
                status={loading ? 'Loading...' : ''}
            />
            <ActionRow
                label="Add to Whitelist"
                onClick={() => {
                    setModalType('whitelist');
                    setShowModal(true);
                }}
                status={loading ? 'Loading...' : ''}
            />

            <AddToDomainModal
                showModal={showModal}
                onClose={() => setShowModal(false)}
                domain={domain}
                setDomain={setDomain}
                onAdd={handleAddDomain}
                title={modalType === 'blacklist' ? 'Blacklist Domain' : 'Whitelist Domain'}
                color={modalType === 'blacklist' ? 'danger' : 'success'}
            />
        </div>
    );
}

// -------------------- Modal --------------------
function AddToDomainModal({ showModal, onClose, domain, setDomain, onAdd, title, color = 'danger' }) {
    const [isValid, setIsValid] = useState(false);
    const inputRef = useRef(null);
    const regex = /^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/;

    useEffect(() => {
        setIsValid(domain.trim().length > 0 && regex.test(domain.trim().toLowerCase()));
    }, [domain]);

    useEffect(() => {
        if (showModal && inputRef.current) requestAnimationFrame(() => inputRef.current.focus());
    }, [showModal]);

    if (!showModal) return null;

    return (
        <div className="modal fade show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }} onClick={onClose}>
            <div className="modal-dialog modal-dialog-centered" onClick={(e) => e.stopPropagation()}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">{title}</h5>
                        <button type="button" className="btn-close" onClick={onClose}></button>
                    </div>
                    <div className="modal-body">
                        <input
                            ref={inputRef}
                            type="text"
                            className={`form-control ${domain ? (isValid ? 'is-valid' : 'is-invalid') : ''}`}
                            value={domain}
                            onChange={(e) => setDomain(e.target.value)}
                            placeholder="example.com"
                        />
                    </div>
                    <div className="modal-footer">
                        <button className="btn btn-secondary" onClick={onClose}>
                            Cancel
                        </button>
                        <button
                            className={`btn btn-${color}`}
                            onClick={() => isValid && onAdd(domain)}
                            disabled={!isValid}
                        >
                            {color === 'danger' ? 'Block' : 'Add'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

function BlacklistTab({ token, blacklists, setBlacklists }) {
    const [loading, setLoading] = useState(false);
    const [search, setSearch] = useState('');

    const handleRemove = async (d) => {
        if (!confirm(`Remove ${d}?`)) return;
        setLoading(true);
        try {
            await fetcher({ token, category: 'blacklist', type: 'remove', payload: d });
            setBlacklists((prev) => prev.filter((x) => x !== d));
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const filtered = useMemo(() => {
        if (!search) return blacklists;
        const q = search.toLowerCase();
        return blacklists.filter((d) => d.toLowerCase().includes(q));
    }, [blacklists, search]);

    return (
        <div className="p-0">
            <LoadingOverlay visible={loading} />

            <div className="input-group p-2">
                <input
                    type="text"
                    className="form-control"
                    placeholder="Search blacklisted domains..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            {filtered.length === 0 ? (
                <div className="text-muted text-center py-5">
                    {search ? 'No matches found' : 'No blacklisted domains'}
                </div>
            ) : (
                filtered.map((d, i) => (
                    <div key={i} className="d-flex justify-content-between px-3 py-2 border-bottom align-items-center">
                        <span title={d} className="text-truncate">
                            {d}
                        </span>
                        <button
                            className="btn btn-sm btn-outline-danger"
                            disabled={loading}
                            onClick={() => handleRemove(d)}
                        >
                            Remove
                        </button>
                    </div>
                ))
            )}
        </div>
    );
}

function WhitelistTab({ token, whitelists, setWhitelists }) {
    const [loading, setLoading] = useState(false);
    const [search, setSearch] = useState('');

    const handleRemove = async (d) => {
        if (!confirm(`Remove ${d}?`)) return;
        setLoading(true);
        try {
            await fetcher({ token, category: 'whitelist', type: 'remove', payload: d });
            setWhitelists((prev) => prev.filter((x) => x !== d));
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const filtered = useMemo(() => {
        if (!search) return whitelists;
        const q = search.toLowerCase();
        return whitelists.filter((d) => d.toLowerCase().includes(q));
    }, [whitelists, search]);

    return (
        <div className="p-0">
            <LoadingOverlay visible={loading} />

            <div className="input-group p-2">
                <input
                    type="text"
                    className="form-control"
                    placeholder="Search whitelisted domains..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            {filtered.length === 0 ? (
                <div className="text-muted text-center py-5">
                    {search ? 'No matches found' : 'No whitelisted domains'}
                </div>
            ) : (
                filtered.map((d, i) => (
                    <div key={i} className="d-flex justify-content-between px-3 py-2 border-bottom align-items-center">
                        <span title={d} className="text-truncate">
                            {d}
                        </span>
                        <button
                            className="btn btn-sm btn-outline-danger"
                            disabled={loading}
                            onClick={() => handleRemove(d)}
                        >
                            Remove
                        </button>
                    </div>
                ))
            )}
        </div>
    );
}

function HistoryTab({ predictions = [], dnsHistory = [], blacklists = [], whitelists = [] }) {
    const [sortKey, setSortKey] = useState('created');
    const [sortAsc, setSortAsc] = useState(false);
    const [filterText, setFilterText] = useState('');

    // --- Maps predictions to a fast lookup table ---
    const predictionMap = useMemo(() => {
        const map = new Map();
        predictions.forEach(({ domain, probability }) => map.set(domain, probability));
        return map;
    }, [predictions]);

    // --- Helper functions ---
    const getRowClass = (domain) => {
        if (blacklists.includes(domain)) return 'table-danger';
        if (whitelists.includes(domain)) return 'table-success';
        return '';
    };

    const getBadgeProps = (prediction) => {
        if (prediction > 0.9) return { color: 'bg-danger', label: 'High' };
        if (prediction < 0.25) return { color: 'bg-success', label: 'Low' };
        return { color: 'bg-warning text-dark', label: 'Medium' };
    };

    // --- Transform, filter, and sort data ---
    const displayedHistory = useMemo(() => {
        let list = dnsHistory.map((item) => ({
            ...item,
            prediction: predictionMap.get(item.query) ?? item.prediction ?? 0,
        }));

        if (filterText.trim()) {
            const q = filterText.toLowerCase();
            list = list.filter((item) => item.query.toLowerCase().includes(q));
        }

        list.sort((a, b) => {
            let aVal = a[sortKey],
                bVal = b[sortKey];
            if (sortKey === 'prediction') {
                aVal = parseFloat(aVal);
                bVal = parseFloat(bVal);
            }
            if (aVal < bVal) return sortAsc ? -1 : 1;
            if (aVal > bVal) return sortAsc ? 1 : -1;
            return 0;
        });

        return list;
    }, [dnsHistory, predictionMap, sortKey, sortAsc, filterText]);

    const toggleSort = (key) => {
        if (sortKey === key) setSortAsc(!sortAsc);
        else {
            setSortKey(key);
            setSortAsc(true);
        }
    };

    const SortButton = ({ field, label, align = 'start', width }) => (
        <th scope="col" className={`text-${align}`} style={{ width }}>
            <button
                className="btn p-0 d-flex align-items-center justify-content-center w-100"
                onClick={() => toggleSort(field)}
            >
                {label}
                <span className="ms-1">{sortKey === field ? (sortAsc ? '↑' : '↓') : '⇅'}</span>
            </button>
        </th>
    );

    // --- JSX ---
    return (
        <div className="container-fluid p-0">
            <div className="row mb-3 g-2 align-items-center">
                <div className="col-md-6">
                    <input
                        type="text"
                        className="form-control mx-2"
                        placeholder="Filter by domain..."
                        value={filterText}
                        onChange={(e) => setFilterText(e.target.value)}
                    />
                </div>
                <div className="col-md-6">
                    <DnsHistorySummary displayedHistory={displayedHistory} />
                </div>
                <DnsHistoryLegend />
            </div>

            <div className="table-responsive">
                <table className="table table-hover table-striped align-middle mb-0">
                    <thead className="table-light sticky-top">
                        <tr>
                            <SortButton field="query" label="Domain" width="40%" />
                            <SortButton field="created" label="Timestamp" width="25%" />
                            <SortButton field="query_counter" label="Queries" align="center" width="15%" />
                            <SortButton field="prediction" label="Score" align="center" width="20%" />
                        </tr>
                    </thead>
                    <tbody>
                        {displayedHistory.length === 0 ? (
                            <tr>
                                <td colSpan="4" className="text-center text-muted py-5">
                                    {filterText ? 'No results found' : 'No DNS history available'}
                                </td>
                            </tr>
                        ) : (
                            displayedHistory.map((item, i) => {
                                const { color, label } = getBadgeProps(item.prediction);
                                return (
                                    <tr key={i} className={`${getRowClass(item.query)} cursor-pointer`}>
                                        <td className="fw-medium">{item.query}</td>
                                        <td className="text-muted small">{formatTimestamp(item.created)}</td>
                                        <td className="text-center">
                                            <span className="badge bg-info text-dark">{item.query_counter ?? '-'}</span>
                                        </td>
                                        <td className="text-center">
                                            <span
                                                className={`badge ${color} px-3 py-2`}
                                                title={`Score: ${item.prediction.toFixed?.(3) ?? item.prediction}`}
                                            >
                                                {label}
                                                <small className="ms-2 opacity-75">
                                                    ({item.prediction.toFixed?.(2) ?? item.prediction})
                                                </small>
                                            </span>
                                        </td>
                                    </tr>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function NeuralNet({ token }) {
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('actions');
    const [blacklists, setBlacklists] = useState([]);
    const [whitelists, setWhitelists] = useState([]);
    const [predictions, setPredictions] = useState([]);
    const [dnsHistory, setDnsHistory] = useState([]);

    useEffect(() => {
        const fetchBlacklists = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get', category: 'blacklist' });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch metrics');
                if (!json.payload) throw new Error('Payload missing');

                const data = json.payload || [];
                setBlacklists(data);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchBlacklists();
    }, [token]);

    useEffect(() => {
        const fetchWhitelists = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get', category: 'whitelist' });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch metrics');
                if (!json.payload) throw new Error('Payload missing');

                const data = json.payload || [];
                setWhitelists(data);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchWhitelists();
    }, [token]);

    useEffect(() => {
        const fetchDnsHistory = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get', category: 'dns-history' });
                const json = await res.json();

                if (!json.success) throw new Error('Could not fetch metrics');
                if (!json.payload) throw new Error('Payload missing');

                const data = json.payload || [];
                setDnsHistory(data.map((item) => ({ ...item, prediction: 0.5 })));
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchDnsHistory();
    }, [token]);

    const tabs = [
        { id: 'actions', label: 'Actions' },
        { id: 'history', label: 'DNS History' },
        { id: 'blacklist', label: 'Blacklist' },
        { id: 'whitelist', label: 'Whitelist' },
    ];

    return (
        <div className="container py-4">
            <div className="card">
                <div className="card-header">
                    <h6 className="text-white fw-bold">Neural Net</h6>
                    <span className="small text-white opacity-75">Neural Net powered threat detection</span>
                </div>

                <NeuralNetTabs tabs={tabs} activeTab={activeTab} onSelect={setActiveTab} />
                <div className="card-body p-0">
                    {activeTab === 'actions' && (
                        <ActionsTab
                            token={token}
                            dnsHistory={dnsHistory}
                            predictions={predictions}
                            setPredictions={setPredictions}
                            blacklists={blacklists}
                            setBlacklists={setBlacklists}
                            whitelists={whitelists}
                            setWhitelists={setWhitelists}
                        />
                    )}
                    {activeTab === 'history' && (
                        <HistoryTab
                            token={token}
                            predictions={predictions}
                            dnsHistory={dnsHistory}
                            blacklists={blacklists}
                            whitelists={whitelists}
                        />
                    )}
                    {activeTab === 'blacklist' && (
                        <BlacklistTab token={token} blacklists={blacklists} setBlacklists={setBlacklists} />
                    )}
                    {activeTab === 'whitelist' && (
                        <WhitelistTab token={token} whitelists={whitelists} setWhitelists={setWhitelists} />
                    )}
                </div>
            </div>

            <div id="modal-root"></div>
        </div>
    );
}

window.NeuralNet = NeuralNet;
