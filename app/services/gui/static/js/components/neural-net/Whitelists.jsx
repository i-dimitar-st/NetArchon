function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return <div className="loading-overlay ">Loading...</div>;
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

function Whitelists({ token, whitelists, setWhitelists }) {
    const { useState } = React;
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
            setWhitelists((prev) => [...prev, newDomain]);
            updateCount(whitelists.length + 1);
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
            setWhitelists((prev) => prev.filter((item) => item !== url));
            updateCount(whitelists.length - 1);
        } catch (err) {
            alert(err);
        } finally {
            hideLoading();
        }
    };

    const Row = ({ label, onRemove }) => (
        <div className="d-flex justify-content-between align-items-center px-4 py-3 border-bottom">
            <span className="text-truncate">{label}</span>
            <button className="btn btn-sm btn-primary" onClick={onRemove}>
                Remove
            </button>
        </div>
    );

    return (
        <div className="card mb-4 overflow-hidden" style={{ maxHeight: '500px' }}>
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex align-items-center justify-content-between">
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
            <div className="card-body p-0 overflow-auto">
                {whitelists.length === 0 ? (
                    <div className="text-muted text-center py-3 no-whitelist">
                        <em>No whitelisted domains</em>
                    </div>
                ) : (
                    whitelists.map((url, idx) => <Row key={idx} label={url} onRemove={() => removeDomain(url)} />)
                )}
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
