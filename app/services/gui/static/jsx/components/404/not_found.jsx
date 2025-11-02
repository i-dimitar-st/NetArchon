function NotFound() {
    const [title] = React.useState('404 - Not Found');
    const [loading] = React.useState(false); // optional for future use

    const goHome = () => (window.location.href = '/');
    const goBack = () => window.history.back();

    return (
        <div className="card">
            <CardHeader title="404" subtitle="Page Not Found" />
            <div className="card-body text-center p-3">
                <div className="fs-1 text-danger mb-3">404</div>
                <p className="text-muted mb-3">Sorry, the page you are looking for does not exist.</p>
                <div className="d-flex justify-content-center gap-3 flex-wrap">
                    <button className="btn btn-primary" onClick={goHome}>
                        To Dashboard
                    </button>
                    <button className="btn btn-outline-secondary" onClick={goBack}>
                        Back
                    </button>
                </div>
            </div>
        </div>
    );
}
