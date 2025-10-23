function ActionRow({ label, handleClear, status }) {
    return (
        <div className="d-flex justify-content-between align-items-center px-4 py-2 border-bottom">
            <button className="btn btn-primary btn-sm" onClick={handleClear} style={{ minWidth: '100px' }}>
                {label}
            </button>
            <span className="badge bg-secondary" style={{ minWidth: '100px' }}>
                {status}
            </span>
        </div>
    );
}

function DnsActions({ token }) {
    const { useState } = React;
    const [historyCleared, setHistoryCleared] = useState(false);

    const handleClear = async () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;
        await delay();
        try {
            const res = await fetcher({ token, category: 'dns-history', type: 'clear', payload: null });
            if (!res.ok) throw new Error('Server error');
            const jsonRes = await res.json();
            if (!jsonRes.success) throw new Error(jsonRes.error || 'Unknown error');
            setHistoryCleared(true);
            console.info('Clearing DNS History');
        } catch {
            console.error('Failed to clear DNS History');
        }
    };

    return (
        <div className="card">
            <div className="card-header">
                <h6>Actions</h6>
            </div>
            <div className="card-body p-0">
                <ActionRow
                    label="Clear History"
                    handleClear={handleClear}
                    status={historyCleared ? `Cleared` : 'Not Cleared'}
                />
            </div>
        </div>
    );
}

window.DnsActions = DnsActions;
