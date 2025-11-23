const { useState, useEffect } = React;
function ServerError() {
    const [title] = useState('Server Error');
    const [subtitle] = useState('Status 500 Server Error');
    const [loading] = useState(false);
    const handleGoHome = () => (window.location.href = '/');
    const handleGoBack = () => window.history.back();
    const handleRetry = () => window.location.reload();

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title={title} subtitle={subtitle} />
            <div className="card-body text-center">
                <div className="text-danger fs-3 mb-3">500</div>
                <p className="text-muted mb-3">
                    An internal server error occurred. You can return home, retry, or go back.
                </p>

                <div className="d-flex justify-content-center gap-3 flex-wrap">
                    <button className="btn btn-primary" onClick={goHome}>
                        Home
                    </button>
                    <button className="btn btn-outline-secondary" onClick={goBack}>
                        Back
                    </button>
                    <button className="btn btn-outline-primary" onClick={retry}>
                        Retry
                    </button>
                </div>
            </div>
        </div>
    );
}
