const { useState, useEffect, useRef, useMemo } = React;

function ActionsTab({ token, dnsHistory, predictions, setPredictions, setBlacklists, setWhitelists }) {
    const [trainingStatus, setTrainingStatus] = useState('Idle');
    const [historyCleared, setHistoryCleared] = useState(false);
    const [lastUpdated, setLastUpdated] = useState('');

    const [domain, setDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [modalType, setModalType] = useState('blacklist');
    const [loading, setLoading] = useState(false);

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

function AddToDomainModal({ showModal, onClose, domain, setDomain, onAdd, title, color = 'danger' }) {
    const [isValid, setIsValid] = useState(false);
    const inputRef = useRef(null);
    const isDomanRegex = /^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/;

    useEffect(() => {
        setIsValid(domain.trim().length > 0 && isDomanRegex.test(domain.trim().toLowerCase()));
    }, [domain]);

    useEffect(() => {
        if (showModal && inputRef.current) requestAnimationFrame(() => inputRef.current.focus());
    }, [showModal]);

    if (!showModal) return null;

    return (
        <div className="modal fade show d-block" style={{ backgroundColor: 'var(--hover-bg)' }} onClick={onClose}>
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

    const handleRemove = async (domain) => {
        if (!confirm(`Remove ${domain}?`)) return;
        setLoading(true);
        try {
            await fetcher({ token, category: 'blacklist', type: 'remove', payload: domain });
            setBlacklists((prev) => prev.filter((x) => x !== domain));
            console.info(`${domain} removed from blacklists`);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const filtered = useMemo(() => {
        if (!search) return blacklists;
        return blacklists.filter((domain) => domain.toLowerCase().includes(search.toLowerCase()));
    }, [blacklists, search]);

    return (
        <div>
            <LoadingOverlay visible={loading} />
            <div className="input-group p-3">
                <input
                    type="text"
                    className="form-control"
                    placeholder="Search blacklisted domains..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            {filtered.length === 0 ? (
                <div className="text-muted text-center py-4">No blacklisted domains</div>
            ) : (
                filtered.map((domain, index) => (
                    <div
                        key={index}
                        className="d-flex justify-content-between px-3 py-2 border-bottom align-items-center"
                    >
                        <span title={domain} className="text-truncate">
                            {domain}
                        </span>
                        <button
                            className="btn btn-sm btn-outline-danger"
                            disabled={loading}
                            onClick={() => handleRemove(domain)}
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
            <div className="input-group p-3">
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

function HistoryTab({
    predictions = [],
    dnsHistory = [],
    blacklists = [],
    whitelists = [],
    token,
    setBlacklists,
    setWhitelists,
}) {
    const [filterText, setFilterText] = useState('');
    const [sortKey, setSortKey] = useState('query');
    const [sortAsc, setSortAsc] = useState(true);

    const predictionMap = useMemo(() => {
        const map = new Map();
        predictions.forEach(({ domain, probability }) => map.set(domain, probability));
        return map;
    }, [predictions]);

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
            let aVal = a[sortKey];
            let bVal = b[sortKey];

            if (sortKey === 'prediction') {
                aVal = parseFloat(aVal);
                bVal = parseFloat(bVal);
            }

            if (aVal < bVal) return sortAsc ? -1 : 1;
            if (aVal > bVal) return sortAsc ? 1 : -1;
            return 0;
        });

        return list;
    }, [dnsHistory, predictionMap, filterText, sortKey, sortAsc]);

    const getBadgeProps = (prediction) => {
        if (prediction > 0.9) return { color: 'bg-danger', label: 'High' };
        if (prediction < 0.25) return { color: 'bg-success', label: 'Low' };
        return { color: 'bg-warning text-dark', label: 'Medium' };
    };

    const getRowClass = (domain) => {
        if (blacklists.includes(domain)) return 'table-danger';
        if (whitelists.includes(domain)) return 'table-success';
        return '';
    };

    const toggleSort = (key) => {
        if (sortKey === key) setSortAsc(!sortAsc);
        else {
            setSortKey(key);
            setSortAsc(true);
        }
    };

    const handleAddBlacklist = async (domain) => {
        try {
            await fetcher({ token, category: 'blacklist', type: 'add', payload: domain });
            setBlacklists((prev) => [...prev, domain]);
        } catch (err) {
            console.error(err);
        }
    };

    const handleRemoveBlacklist = async (domain) => {
        try {
            await fetcher({ token, category: 'blacklist', type: 'remove', payload: domain });
            setBlacklists((prev) => prev.filter((d) => d !== domain));
        } catch (err) {
            console.error(err);
        }
    };

    const handleAddWhitelist = async (domain) => {
        try {
            await fetcher({ token, category: 'whitelist', type: 'add', payload: domain });
            setWhitelists((prev) => [...prev, domain]);
        } catch (err) {
            console.error(err);
        }
    };

    const handleRemoveWhitelist = async (domain) => {
        try {
            await fetcher({ token, category: 'whitelist', type: 'remove', payload: domain });
            setWhitelists((prev) => prev.filter((d) => d !== domain));
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="p-0">
            <div className="input-group p-3">
                <input
                    type="text"
                    className="form-control"
                    placeholder="Filter by domain..."
                    value={filterText}
                    onChange={(e) => setFilterText(e.target.value)}
                />
            </div>
            <div className="table-responsive m-2 p-2">
                <table className="table table-hover align-middle">
                    <thead className="sticky-top">
                        <tr>
                            <th>
                                <button className="btn p-0" onClick={() => toggleSort('query')}>
                                    Domain {sortKey === 'query' ? (sortAsc ? '↑' : '↓') : '⇅'}
                                </button>
                            </th>
                            <th className="text-center">
                                <button className="btn p-0" onClick={() => toggleSort('prediction')}>
                                    Score {sortKey === 'prediction' ? (sortAsc ? '↑' : '↓') : '⇅'}
                                </button>
                            </th>
                            <th className="text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {displayedHistory.length === 0 ? (
                            <tr>
                                <td colSpan="3" className="text-center text-muted">
                                    {filterText ? 'No results found' : 'No DNS history available'}
                                </td>
                            </tr>
                        ) : (
                            displayedHistory.map((item, i) => {
                                const { color, label } = getBadgeProps(item.prediction);
                                const isBlacklisted = blacklists.includes(item.query);
                                const isWhitelisted = whitelists.includes(item.query);

                                return (
                                    <tr key={i} className={`${getRowClass(item.query)} cursor-pointer`}>
                                        <td className="text-start px-1 py-1">{item.query}</td>
                                        <td className="text-center">
                                            <span className={`badge ${color} px-1 py-1 text-capitalize fs-6`}>
                                                {label} {item.prediction.toFixed(2)}
                                            </span>
                                        </td>
                                        <td className="text-center d-flex justify-content-center gap-2">
                                            {isBlacklisted && (
                                                <button
                                                    className="btn btn-sm btn-outline-danger"
                                                    onClick={() => handleRemoveBlacklist(item.query)}
                                                >
                                                    De-Blacklist
                                                </button>
                                            )}
                                            {isWhitelisted && (
                                                <button
                                                    className="btn btn-sm btn-outline-success"
                                                    onClick={() => handleRemoveWhitelist(item.query)}
                                                >
                                                    De-Whitelist
                                                </button>
                                            )}
                                            {!isBlacklisted && !isWhitelisted && (
                                                <>
                                                    <button
                                                        className="btn btn-sm btn-success"
                                                        onClick={() => handleAddWhitelist(item.query)}
                                                    >
                                                        Whitelist
                                                    </button>
                                                    <button
                                                        className="btn btn-sm btn-danger"
                                                        onClick={() => handleAddBlacklist(item.query)}
                                                    >
                                                        Blacklist
                                                    </button>
                                                </>
                                            )}
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
    const [activeIndex, setActiveIndex] = useState(0);
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
                console.info('Dns history fetched');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchDnsHistory();
    }, [token]);

    const tabs = [
        {
            label: 'Actions',
            component: (
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
            ),
        },
        {
            label: 'DNS History',
            component: (
                <HistoryTab
                    token={token}
                    predictions={predictions}
                    dnsHistory={dnsHistory}
                    blacklists={blacklists}
                    whitelists={whitelists}
                />
            ),
        },
        {
            label: 'Blacklist',
            component: <BlacklistTab token={token} blacklists={blacklists} setBlacklists={setBlacklists} />,
        },
        {
            label: 'Whitelist',
            component: <WhitelistTab token={token} whitelists={whitelists} setWhitelists={setWhitelists} />,
        },
    ];

    return (
        <>
            <div className="card">
                <LoadingOverlay visible={loading} />
                <CardHeader title="Neural Net" subtitle="Neural Net powered threat detection" />
                <TabList tabs={tabs} activeIndex={activeIndex} setActiveIndex={setActiveIndex} />
                <TabContent component={tabs[activeIndex].component} />
            </div>
            <div id="modal-root"></div>
        </>
    );
}
