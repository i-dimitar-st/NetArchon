function AddToBlacklistModal({ showModal, onModalClose, handleAddToBlacklist, newDomain, setNewDomain }) {
    const { useState, useEffect, useRef } = React;
    const [isValid, setIsValid] = useState(false);
    const inputRef = useRef(null);

    const domainPattern = '^(?:[a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}$';
    const domainRegex = new RegExp(domainPattern);

    useEffect(() => {
        const trimmed = newDomain.trim().toLowerCase();
        setIsValid(trimmed.length > 0 && domainRegex.test(trimmed));
    }, [newDomain]);

    useEffect(() => {
        if (showModal && inputRef.current) {
            requestAnimationFrame(() => inputRef.current.focus());
        }
    }, [showModal]);

    const handleAdd = () => {
        if (isValid) handleAddToBlacklist(newDomain.trim());
    };

    if (!showModal) return null;

    return ReactDOM.createPortal(
        <div className="modal fade show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }} onClick={onModalClose}>
            <div className="modal-dialog modal-dialog-centered" onClick={(e) => e.stopPropagation()}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Blacklist Domain</h5>
                        <button type="button" className="btn-close" onClick={onModalClose}></button>
                    </div>
                    <div className="modal-body">
                        <input
                            ref={inputRef}
                            type="text"
                            className={`form-control ${newDomain ? (isValid ? 'is-valid' : 'is-invalid') : ''}`}
                            placeholder="example.com"
                            value={newDomain}
                            onChange={(e) => setNewDomain(e.target.value)}
                            pattern={domainPattern}
                            title="Enter a valid domain, e.g. www.test.com"
                        />
                    </div>
                    <div className="modal-footer">
                        <button className="btn btn-secondary" onClick={onModalClose}>
                            Cancel
                        </button>
                        <button className="btn btn-danger" onClick={handleAdd} disabled={!isValid}>
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
        <div className="d-flex justify-content-between align-items-center px-3 py-1 border-bottom">
            <span className="text-truncate" title={label}>
                {label}
            </span>
            <button className="btn btn-sm btn-outline-danger" onClick={onRemove} disabled={loading}>
                Remove
            </button>
        </div>
    );

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <div className="card-header">
                <div className="d-flex align-items-center gap-2">
                    <h6>Blacklist</h6>
                    <span className="badge bg-secondary">{blacklists.length}</span>
                </div>
                <button className="btn btn-sm btn-primary" onClick={() => setShowModal(true)}>
                    Add To Blacklist
                </button>
            </div>
            <div className="card-body p-0">
                {blacklists.length === 0 ? (
                    <div className="text-muted text-center py-5">No blacklisted domains</div>
                ) : (
                    blacklists.map((url, idx) => (
                        <Row key={idx} label={url} onRemove={() => handleRemoveFromBlacklist(url)} />
                    ))
                )}
            </div>

            <AddToBlacklistModal
                showModal={showModal}
                onModalClose={() => setShowModal(false)}
                handleAddToBlacklist={handleAddToBlacklist}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Blacklists = Blacklists;
