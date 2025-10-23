function DashboardCard({ title, data = {} }) {
    return (
        <div className="card">
            <div className="card-header">
                <h6>{formatStatsKey(title)}</h6>
            </div>

            <div className="card-body p-3">
                {Object.entries(data).map(([key, value]) => {
                    return (
                        <div key={key} className="d-flex justify-content-between align-items-start">
                            <div className="text-muted text-uppercase small">{formatStatsKey(key)}</div>
                            <div className="d-flex justify-content-between align-items-end">
                                <div className="fw-semibold">{value.value}</div>
                                <div className="text-muted ms-2" style={{ minWidth: '30px' }}>
                                    {value.unit}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function Dashboard({ token }) {
    const { useState, useEffect } = React;
    const [dashboardData, setDashboardData] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get-dashboard-cards' });
                const { payload, success } = await res.json();
                if (!success) throw new Error('Could not fetch data');
                setDashboardData(payload || {});
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token]);

    return (
        <>
            {Object.entries(dashboardData).map(([title, cardData]) => (
                <div className="col-md-6 col-lg-4" key={title}>
                    <LoadingOverlay visible={loading} />
                    <DashboardCard title={title} data={cardData} />
                </div>
            ))}
        </>
    );
}

window.Dashboard = Dashboard;
