function Spec({ title, data }) {
    if (typeof data !== 'object' || data === null) {
        console.warn(`${title} expected an object but received:`, data);
        return null;
    }

    return (
        <div className="card h-100">
            <h6 className="card-header mb-0 fw-bold text-uppercase">{title.replace(/_/g, ' ')}</h6>
            <div className="card-body" style={{ overflowY: 'auto' }}>
                {Object.entries(data).map(([key, value]) => (
                    <div className="row mb-1">
                        <div className="col-7 text-muted text-uppercase small" style={{ minWidth: '150px' }}>
                            {key.replaceAll('_', ' ')}
                        </div>
                        <div className="col-5 fw-semibold small text-break">{String(value)}</div>
                    </div>
                ))}
            </div>
        </div>
    );
}

function Specs({ config }) {
    return (
        <div className="row g-4 mb-4">
            {Object.entries(config).map(([key, value]) => (
                <div className="col-12 col-md-6 col-lg-4" key={key}>
                    <Spec title={key} data={value} />
                </div>
            ))}
        </div>
    );
}
window.Specs = Specs;
window.Spec = Spec;
