function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return <div className="loading-overlay ">Loading...</div>;
}

function AddBlacklistModal({ show, onClose, onAdd, newDomain, setNewDomain }) {
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
                        <h5 className="modal-title">Blacklist Domain</h5>
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
                        <button type="button" className="btn btn-secondary" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="button" className="btn btn-primary" onClick={onAdd}>
                            Add
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );

    return ReactDOM.createPortal(modalContent, document.getElementById('modal-root'));
}

function Blacklists({ token, blacklists, setBlacklists }) {
    const { useState } = React;
    const [newDomain, setNewDomain] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [loading, setLoading] = useState(false);

    const showLoading = () => setLoading(true);
    const hideLoading = () => setLoading(false);

    const addDomain = async () => {
        if (!newDomain.trim()) return;
        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ category: 'blacklist', type: 'add', payload: newDomain }),
            });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setBlacklists((prev) => [...prev, newDomain]); // <- update parent state
            setNewDomain('');
            setShowModal(false);
        } catch (err) {
            console.error(err);
            alert(err.message || 'Error');
        } finally {
            hideLoading();
        }
    };

    const removeDomain = async (url) => {
        if (!confirm(`Remove ${url} from blacklist?`)) return;
        showLoading();
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ category: 'blacklist', type: 'remove', payload: url }),
            });
            if (!res.ok) throw new Error('Server error');
            await res.json();
            setBlacklists((prev) => prev.filter((item) => item !== url)); // <- update parent state
        } catch (err) {
            console.error(err);
            alert(err.message || 'Error');
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
        <div className="card mb-4 position-relative" style={{ maxHeight: '500px' }}>
            <LoadingOverlay visible={loading} />
            <div className="card-header d-flex align-items-center justify-content-between">
                <div className="d-flex align-items-center gap-2">
                    <h5 className="mb-0 fw-bold">Blacklist</h5>
                    <span className="badge bg-secondary" id="blacklistCount">
                        {blacklists.length}
                    </span>
                </div>
                <button className="btn btn-sm btn-primary" onClick={() => setShowModal(true)}>
                    Add
                </button>
            </div>
            <div className="card-body p-0 overflow-auto">
                {blacklists.length === 0 ? (
                    <div className="text-muted text-center py-3">
                        <em>No blacklisted domains</em>
                    </div>
                ) : (
                    blacklists.map((url, idx) => <Row key={idx} label={url} onRemove={() => removeDomain(url)} />)
                )}
            </div>

            <AddBlacklistModal
                show={showModal}
                onClose={() => setShowModal(false)}
                onAdd={addDomain}
                newDomain={newDomain}
                setNewDomain={setNewDomain}
            />
        </div>
    );
}

window.Blacklists = Blacklists;
