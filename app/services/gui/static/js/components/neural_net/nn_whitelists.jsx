function AddToWhitelistModal({ showModal, onModalClose, handleAddToWhitelist, newDomain, setNewDomain }) {
    const { useState, useEffect, useRef } = React;
    const [isValid, setIsValid] = useState(false);
    const [domainPattern] = useState('^(?:[a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}$');
    const [domainRegex] = useState(new RegExp(domainPattern));
    const inputRef = useRef(null);

    useEffect(() => {
        const trimmedDomain = newDomain.trim().toLowerCase();
        setIsValid(trimmedDomain.length > 0 && domainRegex.test(trimmedDomain));
    }, [newDomain]);

    useEffect(() => {
        if (showModal && inputRef.current) {
            requestAnimationFrame(() => inputRef.current.focus());
        }
    }, [showModal]);

    const handleAdd = () => {
        if (isValid) {
            handleAddToWhitelist(newDomain.trim());
        }
    };

    const handleKeyDown = (event) => {
        if (event.key === 'Enter' && isValid) {
            handleAdd();
        }
    };

    if (!showModal) return null;

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
                        <h6 className="modal-title">Add Domain to Whitelist</h6>
                        <button type="button" className="btn-close" onClick={onModalClose} aria-label="Close"></button>
                    </div>
                    <div className="modal-body">
                        <label htmlFor="domainInput" className="form-label">
                            Domain
                        </label>
                        <input
                            ref={inputRef}
                            id="domainInput"
                            type="text"
                            className={`form-control ${newDomain ? (isValid ? 'is-valid' : 'is-invalid') : ''}`}
                            placeholder="example.com"
                            value={newDomain}
                            onChange={(e) => setNewDomain(e.target.value)}
                            onKeyDown={handleKeyDown}
                        />
                        {newDomain && !isValid && (
                            <div className="invalid-feedback d-block">
                                Please enter a valid domain (e.g., example.com or subdomain.example.com)
                            </div>
                        )}
                        <div className="form-text">
                            Enter a domain without protocol (e.g., example.com, not https://example.com)
                        </div>
                    </div>
                    <div className="modal-footer">
                        <button className="btn btn-secondary" onClick={onModalClose}>
                            Cancel
                        </button>
                        <button className="btn btn-success" onClick={handleAdd} disabled={!isValid}>
                            Add to Whitelist
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

    const handleAddToWhitelist = async (domain) => {
        setLoading(true);
        try {
            const trimmedDomain = domain.trim().toLowerCase();
            if (whitelists.find((whitelist) => whitelist.toLowerCase() === trimmedDomain))
                throw new Error('This domain is already in the whitelist');

            const res = await fetcher({ token, category: 'whitelist', type: 'add', payload: trimmedDomain });
            await delay();
            if (!res.ok) throw new Error(`Server error: ${res.status}`);
            await res.json();

            setWhitelists((prev) => [...prev, trimmedDomain]);
            setNewDomain('');
            setShowModal(false);
        } catch (err) {
            console.error('Error adding to whitelist:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleRemoveFromWhitelist = async (domain) => {
        if (!confirm(`Are you sure you want to remove "${domain}" from the whitelist?`)) return;
        setLoading(true);
        try {
            const res = await fetcher({ token, category: 'whitelist', type: 'remove', payload: domain });
            await delay();
            if (!res.ok) throw new Error(`Server error: ${res.status}`);
            setWhitelists((prev) => prev.filter((item) => item !== domain));
        } catch (err) {
            console.error('Error removing from whitelist:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const fetchWhitelists = async () => {
            try {
                setLoading(true);
                const res = await fetcher({ token, type: 'get', category: 'whitelist' });
                if (!res.ok) throw new Error(`Server error: ${res.status}`);
                const { success, payload } = await res.json();
                if (!success || !Array.isArray(payload)) throw new Error('Invalid response format');
                setWhitelists(payload);
            } catch (err) {
                console.error('Error fetching whitelists:', err);
            } finally {
                setLoading(false);
            }
        };
        if (token) fetchWhitelists();
    }, [token, setWhitelists]);

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
                    <h6>Whitelist</h6>
                    <span className="badge bg-secondary">{whitelists.length}</span>
                </div>
                <button className="btn btn-sm btn-primary" onClick={() => setShowModal(true)} disabled={loading}>
                    Add To Whitelist
                </button>
            </div>

            <div className="card-body p-0">
                {whitelists.length === 0 ? (
                    <div className="text-muted text-center py-5">
                        <p className="mb-0">No whitelisted domains</p>
                    </div>
                ) : (
                    whitelists.map((url, idx) => (
                        <Row key={`${url}-${idx}`} label={url} onRemove={() => handleRemoveFromWhitelist(url)} />
                    ))
                )}
            </div>

            <AddToWhitelistModal
                showModal={showModal}
                onModalClose={() => {
                    setShowModal(false);
                    setNewDomain('');
                }}
                handleAddToWhitelist={handleAddToWhitelist}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Whitelists = Whitelists;
