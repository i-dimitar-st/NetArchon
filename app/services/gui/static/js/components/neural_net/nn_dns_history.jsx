function generateDomainPredictionsMap(predictions = []) {
    const predictionsMapping = {};

    predictions.forEach((each) => {
        if (each.domain) {
            const domainLowerCase = each.domain.toLowerCase();
            predictionsMapping[domainLowerCase] = each.probability;
        }
    });

    return predictionsMapping;
}

function DomainRow({
    query,
    counter,
    timestamp,
    prediction = 0.5,
    blacklists,
    whitelists,
    handleAddToWhitelist,
    handleAddToBlacklist,
}) {
    return (
        <div
            className={`d-flex flex-column flex-sm-row justify-content-between align-items-start align-items-sm-center px-3 border-bottom ${getRowPredictionClass(
                query,
                blacklists,
                whitelists
            )}`}
        >
            <span
                className={`small text-truncate w-100 ${prediction > 0.95 ? 'text-danger' : 'text-muted'}`}
                style={{ maxWidth: '100%' }}
                title={query}
            >
                {query.toLowerCase()}
            </span>

            <div className="d-flex align-items-center gap-2 flex-nowrap ms-sm-auto">
                <span className="badge bg-secondary">{counter}</span>
                {prediction !== undefined && (
                    <span className={getPredictionBadgeClass(prediction)}>{(prediction * 100).toFixed(0)}</span>
                )}
                <button className="btn btn-sm btn-success" onClick={() => handleAddToWhitelist(query)}>
                    <span className="">Allow</span>
                </button>
                <button className="btn btn-sm btn-danger" onClick={() => handleAddToBlacklist(query)}>
                    <span className="">Block</span>
                </button>
            </div>
        </div>
    );
}

function HistoryDomains({ token, blacklists = [], whitelists = [], predictions = [] }) {
    const { useState, useEffect, useMemo } = React;
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [defaultPrediction, setDefaultPrediction] = useState(0.5);

    const domainPredictionsMap = useMemo(() => generateDomainPredictionsMap(predictions), [predictions]);

    useEffect(() => {
        console.log('Predictions updated');
    }, [domainPredictionsMap]);

    const sortedHistory = useMemo(() => {
        return [...history].sort((a, b) => {
            const probA = domainPredictionsMap[a?.query?.toLowerCase()] ?? 0.5;
            const probB = domainPredictionsMap[b?.query?.toLowerCase()] ?? 0.5;
            return probB - probA;
        });
    }, [history, domainPredictionsMap]);

    const handleAddToWhitelist = async (domain) => {
        setLoading(true);
        try {
            const res = await fetcher({ token, category: 'whitelist', type: 'add', payload: domain });
            if (!res.ok) throw new Error('Failed to add to whitelist');
            console.info(`${domain} added to Whitelist`);
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleAddToBlacklist = async (domain) => {
        setLoading(true);
        try {
            const res = await fetcher({ token, category: 'blacklist', type: 'add', payload: domain });
            if (!res.ok) throw new Error('Failed to add to blacklist');
            console.info(`${domain} added to Blacklist`);
        } catch (err) {
            console.error(err);
            alert(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        setLoading(true);
        (async () => {
            try {
                const res = await fetcher({ token, category: 'dns-history', type: 'get' });
                if (!res.ok) throw new Error('Server error');
                const data = await res.json();
                if (!data.success || !Array.isArray(data.payload)) throw new Error('Invalid response');
                setHistory(data.payload);
                console.info('DNS History loaded');
            } catch (err) {
                console.error('Error Fetchin DNS History', err);
            } finally {
                setLoading(false);
            }
        })();
    }, [token]);

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <div className="d-flex align-items-center gap-2">
                    <h6 className="">DNS Query History</h6>
                    <span className="badge bg-secondary">{history.length}</span>
                </div>
            </div>
            <div className="card-body p-0">
                {sortedHistory.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No history</em>
                    </div>
                ) : (
                    sortedHistory.map((item, idx) => (
                        <DomainRow
                            key={idx}
                            query={item?.query || 'unknown'}
                            counter={item?.query_counter || 0}
                            timestamp={formatTimestamp(item?.created)}
                            prediction={domainPredictionsMap[item?.query?.toLowerCase()] || defaultPrediction}
                            blacklists={blacklists}
                            whitelists={whitelists}
                            handleAddToWhitelist={handleAddToWhitelist}
                            handleAddToBlacklist={handleAddToBlacklist}
                        />
                    ))
                )}
            </div>
        </div>
    );
}

window.HistoryDomains = HistoryDomains;
