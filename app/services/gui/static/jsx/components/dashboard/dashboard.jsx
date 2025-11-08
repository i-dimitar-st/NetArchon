const { useState, useEffect } = React;

function DashboardCard({ data = {} }) {
    return (
        <div className="card-body">
            {Object.entries(data).map(([key, value]) => {
                return (
                    <div key={key} className="d-flex justify-content-between align-items-start">
                        <div className="text-muted text-uppercase small">{formatStatsKey(key)}</div>
                        <div className="d-flex justify-content-between align-items-end">
                            <div className="fw-semibold">{value.value}</div>
                            <div className="text-muted text-uppercase small ms-2" style={{ minWidth: '40px' }}>
                                {value.unit}
                            </div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

function Dashboard({ token }) {
    const { useState, useEffect } = React;
    const [dashboardData, setDashboardData] = useState({});
    const [activeIndex, setActiveIndex] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const res = await fetcher({ token, type: 'get-dashboard-cards' });
                const { payload, success } = await res.json();

                if (!success) throw new Error('Could not fetch data');
                if (!payload) throw new Error('Data not JSON');

                setDashboardData(payload || {});
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
