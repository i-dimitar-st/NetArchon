function AddToBlacklistModal({ showModal, onModalClose, onModalAdd, newDomain, setNewDomain }) {
    const { useState, useEffect } = React;
    const [isValidDomain, setIsValidDomain] = useState(false);
    const [domainPattern] = useState('^(?:[a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}$');
    const [domainRegex] = useState(new RegExp(domainPattern));

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
            <div className="modal-dialog modal-dialog-centered" onClick={(e) => e.stopPropagation()}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Blacklist Domain</h5>
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
                        <button className="btn btn-danger" onClick={handleAdd} disabled={!isValidDomain}>
                            Block
                        </button>
                    </div>
                </div>
            </div>
        </div>,
        document.getElementById('modal-root')
    );
}

function Blacklists({ token, blacklists, setBlacklists }) {
    const { useState, useEffect } = React;
    const [newDomain, setNewDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [loading, setLoading] = useState(false);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const getBlacklists = async () => {
        const res = await fetcher({ token, type: 'get', category: 'blacklist' });
        if (!res.ok) throw new Error('Server error');
        const data = await res.json();
        if (!data.success || !Array.isArray(data.payload)) throw new Error('Invalid response format');
        return data.payload;
    };

    const handleAddToBlacklist = async (domain) => {
        showLoading();
        try {
            const res = await fetcher({ token, category: 'blacklist', type: 'add', payload: domain });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setBlacklists((prev) => [...prev, domain]);
            setNewDomain('');
            setShowModal(false);
        } catch (err) {
            console.error(err);
            alert(err.message || 'Error adding domain');
        } finally {
            hideLoading();
        }
    };

    const handleRemoveFromBlacklist = async (url) => {
        if (!confirm(`Remove ${url} from blacklist?`)) return;
        showLoading();
        try {
            const res = await fetcher({ token, category: 'blacklist', type: 'remove', payload: url });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setBlacklists((prev) => prev.filter((item) => item !== url));
        } catch (err) {
            console.error(err);
            alert(err.message || 'Error removing domain');
        } finally {
            hideLoading();
        }
    };

    useEffect(() => {
        const fetchAndSetBlacklists = async () => {
            showLoading();
            try {
                const data = await getBlacklists();
                setBlacklists(data);
            } catch (err) {
                console.error(err);
                alert(err.message || 'Error fetching blacklists');
            } finally {
                hideLoading();
            }
        };
        fetchAndSetBlacklists();
    }, [token]);

    const Row = ({ label, onRemove }) => (
        <div className="d-flex justify-content-between align-items-center px-4 py-3 border-bottom">
            <span className="text-truncate">{label}</span>
            <button className="btn btn-sm btn-danger" onClick={onRemove}>
                Remove
            </button>
        </div>
    );

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold">Blacklist</h5>
                    <span className="badge bg-secondary">{blacklists.length}</span>
                </div>
                <button className="btn btn-sm btn-success" onClick={() => setShowModal(true)}>
                    Add
                </button>
            </div>
            <div className="card-body">
                {blacklists.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No blacklisted domains</em>
                    </div>
                ) : (
                    blacklists.map((url, idx) => (
                        <Row key={idx} label={url} onRemove={() => handleRemoveFromBlacklist(url)} />
                    ))
                )}
            </div>

            <AddToBlacklistModal
                showModal={showModal}
                onModalClose={() => setShowModal(false)}
                onModalAdd={handleAddToBlacklist}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Blacklists = Blacklists;
