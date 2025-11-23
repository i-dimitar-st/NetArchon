const { useState, useEffect } = React;

function normalizeDashboardData(data) {
    const normalized = {};
    for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'object' && value?.value !== undefined) {
            normalized[key] = value;
        } else {
            normalized[key] = { value, unit: '' };
        }
    }
    return normalized;
}

function DashboardCard({ data = {} }) {
    const stats = normalizeDashboardData(data);

    return (
        <div className="card-body">
            {Object.entries(stats).map(([key, { value, unit }]) => (
                <div key={key} className="d-flex justify-content-between align-items-center mb-2">
                    <span className="text-capitalize text-muted small">{formatStatsKey(key)}</span>
                    <div className="d-flex align-items-baseline">
                        <span className="fw-bold me-1">{value}</span>
                        {unit && <span className="text-muted small">{unit}</span>}
                    </div>
                </div>
            ))}
        </div>
    );
}

function Dashboard({ token }) {
    const [dashboardData, setDashboardData] = useState({});
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const reqBody = { type: 'get', resource: 'data', category: 'dashboard' };
                const res = await fetcher({ token, body: reqBody });
                const jsonRes = await res.json();

                if (!res.ok) throw new Error('Server error');
                if (!jsonRes?.payload?.dashboard) throw new Error(jsonRes.error || 'Unknown error');

                setDashboardData(jsonRes.payload.dashboard || {});
                console.info('Dashboard card data fetched.');
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token]);

    const tabs = Object.entries(dashboardData || {}).map(([key, value]) => ({
        label: key,
        component: <DashboardCard data={value} />,
    }));

    const activeTab = tabs[activeIndex];

    return (
        <div className="card">
            <LoadingOverlay visible={loading} />
            <CardHeader title="Dashboard" subtitle="System Summaries" />
            {tabs.length > 0 && (
                <>
                    <TabList tabs={tabs} activeIndex={activeIndex} setActiveIndex={setActiveIndex} />
                    <TabContent component={activeTab.component} />
                </>
            )}
        </div>
    );
}
