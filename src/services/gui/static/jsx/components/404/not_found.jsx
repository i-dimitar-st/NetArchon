const { useState, useEffect } = React;

function NotFound() {
    const [title] = useState('Not Found');
    const [subtitle] = useState('Status 404 does not exist');
    const [loading] = useState(false);
    const handleGoHome = () => (window.location.href = '/');
    const handleGoBack = () => window.history.back();

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title={title} subtitle={subtitle} />
            <div className="card-body text-center">
                <div className="text-danger fs-3 mb-3">404</div>
                <p className="text-muted">Sorry, the page you are looking for does not exist.</p>
                <div className="d-flex justify-content-center gap-2">
                    <button className="btn btn-primary" onClick={handleGoHome}>
                        To Dashboard
                    </button>
                    <button className="btn btn-outline-secondary" onClick={handleGoBack}>
                        Back
                    </button>
                </div>
            </div>
        </div>
    );
}
