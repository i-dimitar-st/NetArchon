function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return (
        <div
            style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                background: 'rgba(0,0,0,0.5)',
                zIndex: 1050,
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                color: 'white',
                fontSize: '1.5rem',
            }}
        >
            Loading...
        </div>
    );
}

function AddWhitelistModal({ show, onClose, onAdd, newDomain, setNewDomain }) {
    if (!show) return null;

    const modalContent = (
        <div
            className="modal fade show d-block"
            tabIndex="-1"
            style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
            onClick={onClose}
        >
            <div className="modal-dialog modal-dialog-centered" onClick={(e) => e.stopPropagation()}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Add Whitelist Domain</h5>
                        <button type="button" className="btn-close" onClick={onClose}></button>
                    </div>
                    <div className="modal-body">
                        <input
                            type="text"
                            className="form-control"
                            placeholder="example.com"
                            value={newDomain}
                            onChange={(e) => setNewDomain(e.target.value)}
                            autoFocus
                        />
                    </div>
                    <div className="modal-footer">
                        <button className="btn btn-secondary" onClick={onClose}>
                            Cancel
                        </button>
                        <button className="btn btn-primary" onClick={onAdd}>
                            Add
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );

    return ReactDOM.createPortal(modalContent, document.getElementById('modal-root'));
}

function Whitelists({ token, initialWhitelists }) {
    const { useState } = React;
    const [whitelist, setWhitelist] = useState(initialWhitelists || []);
    const [newDomain, setNewDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [loading, setLoading] = useState(false);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const updateCount = (count) => {
        document.getElementById('whitelistCount').textContent = count;
    };

    const addDomain = async () => {
        if (!newDomain.trim()) return;
        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ category: 'whitelist', type: 'add', payload: newDomain }),
            });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setWhitelist((prev) => [...prev, newDomain]);
            updateCount(whitelist.length + 1);
            setNewDomain('');
            setShowModal(false);
        } catch (err) {
            alert(err);
        } finally {
            hideLoading();
        }
    };

    const removeDomain = async (url) => {
        if (!confirm(`Remove ${url} from whitelist?`)) return;
        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ category: 'whitelist', type: 'remove', payload: url }),
            });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setWhitelist((prev) => prev.filter((item) => item !== url));
            updateCount(whitelist.length - 1);
        } catch (err) {
            alert(err);
        } finally {
            hideLoading();
        }
    };

    return (
        <div className="card mb-4 overflow-hidden">
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex align-items-center justify-content-between">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold" style={{ color: 'var(--text-secondary)' }}>
                        Whitelist
                    </h5>
                    <span className="badge bg-success" id="whitelistCount">
                        {whitelist.length}
                    </span>
                </div>
                <button className="btn btn-sm btn-success" onClick={() => setShowModal(true)}>
                    Add
                </button>
            </div>
            <div className="card-body p-2">
                <div className="overflow-y-auto w-100" style={{ maxHeight: '500px' }}>
                    {whitelist.length === 0 ? (
                        <div className="text-muted text-center py-3 no-whitelist">
                            <em>No whitelisted domains</em>
                        </div>
                    ) : (
                        whitelist.map((url, idx) => (
                            <div
                                key={idx}
                                className="d-flex align-items-center justify-content-between bg-light border-bottom px-3 py-2 mb-2 whitelist-item"
                                data-domain={url}
                            >
                                <span className="text-truncate me-2" style={{ maxWidth: 'calc(100% - 60px)' }}>
                                    {url}
                                </span>
                                <button
                                    className="btn btn-sm btn-success"
                                    onClick={() => removeDomain(url)}
                                    title={`Remove ${url} from whitelist`}
                                    aria-label={`Remove ${url} from whitelist`}
                                >
                                    Remove
                                </button>
                            </div>
                        ))
                    )}
                </div>
            </div>

            <AddWhitelistModal
                show={showModal}
                onClose={() => setShowModal(false)}
                onAdd={addDomain}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Whitelists = Whitelists;
