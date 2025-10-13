function AddToWhitelistModal({ showModal, onModalClose, onModalAdd, newDomain, setNewDomain }) {
    const { useState, useEffect } = React;
    const [isValidDomain, setIsValidDomain] = useState(false);
    const [domainPattern, setDomainPattern] = useState('^(?:[a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}$');
    const [domainRegex, setDomainRegex] = useState(new RegExp(domainPattern));

    useEffect(() => {
        setIsValidDomain(domainRegex.test(newDomain));
    }, [newDomain, domainRegex]);

    if (!showModal) return null;

    const handleAdd = () => {
        if (isValidDomain) onModalAdd(newDomain);
    };

    return ReactDOM.createPortal(
        <div
            className="modal fade show d-block"
            tabIndex="-1"
            style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
            onClick={onModalClose}
        >
            <div className="modal-dialog modal-dialog-centered" onClick={(event) => event.stopPropagation()}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Whitelist Domain</h5>
                        <button type="button" className="btn-close" onClick={onModalClose}></button>
                    </div>
                    <div className="modal-body">
                        <input
                            type="text"
                            className="form-control"
                            placeholder="example.com"
                            value={newDomain}
                            onChange={(e) => {
                                setNewDomain(e.target.value);
                                setIsValidDomain(domainRegex.test(e.target.value));
                            }}
                            autoFocus
                            pattern={domainPattern}
                            title="Enter a valid domain, e.g. www.test.com"
                        />
                    </div>
                    <div className="modal-footer">
                        <button className="btn btn-secondary" onClick={onModalClose}>
                            Cancel
                        </button>
                        <button className="btn btn-success" onClick={handleAdd} disabled={!isValidDomain}>
                            Allow
                        </button>
                    </div>
                </div>
            </div>
        </div>,
        document.getElementById('modal-root')
    );
}

function Whitelists({ token, whitelists, setWhitelists }) {
    const { useState, useEffect } = React;
    const [newDomain, setNewDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [loading, setLoading] = useState(false);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const getWhitelists = async (token) => {
        const res = await fetcher({ token, type: 'get', category: 'whitelist' });
        if (!res.ok) throw new Error('Server error');
        const data = await res.json();
        if (!data.success || !Array.isArray(data.payload)) throw new Error('Invalid response format');
        return data.payload;
    };

    const handleAddToWhitelist = async () => {
        showLoading();
        try {
            const res = await fetcher({ token, category: 'whitelist', type: 'add', payload: newDomain });
            await delay();
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setWhitelists((prev) => [...prev, newDomain]);
            setNewDomain('');
            setShowModal(false);
        } catch (err) {
            alert(err);
        } finally {
            hideLoading();
        }
    };

    const handleRemoveFromWhitelist = async (url) => {
        showLoading();
        try {
            const res = await fetcher({ token, category: 'whitelist', type: 'remove', payload: url });
            await delay();
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setWhitelists((prev) => prev.filter((item) => item !== url));
        } catch (err) {
            console.error(err);
            alert(err.message || 'Error');
        } finally {
            hideLoading();
        }
    };

    useEffect(() => {
        const fetchAndSetWhitelists = async () => {
            showLoading();
            try {
                const data = await getWhitelists(token);
                setWhitelists(data);
            } catch (err) {
                console.error(err);
                alert(err.message || 'Error fetching blacklists');
            } finally {
                hideLoading();
            }
        };
        fetchAndSetWhitelists();
    }, []);

    const Row = ({ label, onRemove }) => (
        <div className="d-flex justify-content-between align-items-center px-4 py-3 border-bottom">
            <span className="text-truncate">{label}</span>
            <button className="btn btn-sm btn-primary" onClick={onRemove}>
                Remove
            </button>
        </div>
    );

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold">Whitelist</h5>
                    <span className="badge bg-secondary" id="whitelistCount">
                        {whitelists.length}
                    </span>
                </div>
                <button className="btn btn-sm btn-primary" onClick={() => setShowModal(true)}>
                    Add
                </button>
            </div>
            <div className="card-body">
                {whitelists.length === 0 ? (
                    <div className="text-muted text-center py-3 no-whitelist">
                        <em>No whitelisted domains</em>
                    </div>
                ) : (
                    whitelists.map((url, idx) => (
                        <Row key={idx} label={url} onRemove={() => handleRemoveFromWhitelist(url)} />
                    ))
                )}
            </div>

            <AddToWhitelistModal
                showModal={showModal}
                onModalClose={() => setShowModal(false)}
                onModalAdd={handleAddToWhitelist}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Whitelists = Whitelists;
