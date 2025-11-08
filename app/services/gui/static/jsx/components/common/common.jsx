function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return (
        <div
            className="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center bg-white bg-opacity-75"
            style={{ zIndex: 10 }}
        >
            <div className="text-center">
                <div className="spinner-border text-primary" role="status" />
                <div className="fs-6 text-muted">Loading...</div>
            </div>
        </div>
    );
}

function NoData() {
    return (
        <div className="card-body text-center py-5">
            <div className="text-muted mb-2">
                <i className="bi bi-graph-up" style={{ fontSize: '3rem' }}></i>
            </div>
            <p className="text-muted mb-0">No Data</p>
        </div>
    );
}

function TabBottomBorder() {
    return (
        <div
            className={`position-absolute bottom-0 start-0 w-100 bg-primary`}
            style={{ height: '3px', borderRadius: '3px 3px 0 0' }}
        />
    );
}

function CardHeader({ title, subtitle }) {
    return (
        <div className="card-header px-4 py-2">
            <div className="d-flex align-items-center gap-2">
                <h6 className="m-0 p-0 text-white fw-bold text-capitalize">{title}</h6>
            </div>
            <span className="m-0 p-0 small text-white opacity-75 text-capitalize">{subtitle}</span>
        </div>
    );
}

function TabList({ activeIndex, setActiveIndex, tabs }) {
    return (
        <div className="card-tabs">
            <ul role="tablist" className="nav nav-tabs">
                {tabs.map((tab, i) => (
                    <li key={i} role="presentation" className="nav-item">
                        <button
                            className={`nav-link border-0 position-relative fw-semibold ${
                                i === activeIndex ? 'active' : ''
                            }`}
                            onClick={() => setActiveIndex(i)}
                            type="button"
                            role="tab"
                            style={{ color: i === activeIndex ? 'var(--bs-primary)' : 'var(--bs-secondary)' }}
                        >
                            <span className="text-uppercase small">{tab.label.replaceAll('_', ' ')}</span>
                            {i === activeIndex && <TabBottomBorder />}
                        </button>
                    </li>
                ))}
            </ul>
        </div>
    );
}

function TabContent({ component }) {
    return <div className="card-body p-0">{component}</div>;
}

function ActionRow({ label, onClick, status }) {
    return (
        <div className="d-flex justify-content-between align-items-center px-4 py-2 border-bottom">
            <button
                className="btn btn-primary btn-sm rounded shadow-sm"
                onClick={onClick}
                style={{ minWidth: '110px', fontWeight: 500 }}
            >
                {label}
            </button>
            <span
                className="badge rounded-pill bg-secondary text-truncate"
                style={{ maxWidth: '120px', textAlign: 'center', fontWeight: 500 }}
            >
                {status}
            </span>
        </div>
    );
}
