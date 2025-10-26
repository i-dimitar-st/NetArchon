function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return (
        <div
            className="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center bg-white bg-opacity-75"
            style={{ zIndex: 10 }}
        >
            <div className="text-center">
                <div className="spinner-border text-primary mb-2" role="status" />
                <div className="small text-muted">Loading...</div>
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

window.LoadingOverlay = LoadingOverlay;
window.NoData = NoData;
