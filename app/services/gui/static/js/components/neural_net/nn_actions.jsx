const ActionRow = ({ label, onClick, status }) => (
    <div className="d-flex justify-content-between align-items-center px-4 py-2 border-bottom">
        <button className="btn btn-primary btn-sm" onClick={onClick} style={{ minWidth: '100px' }}>
            {label}
        </button>
        <span className="badge bg-secondary" style={{ minWidth: '100px' }}>
            {status}
        </span>
    </div>
);

function Actions({ token, dnsHistory = [], predictions, setPredictions }) {
    const { useState } = React;
    const [trainingStatus, setTrainingStatus] = useState('Idle');
    const [historyCleared, setHistoryCleared] = useState(false);
    const [lastUpdated, setLastUpdated] = useState('');

    const handleFetchTimestamp = async () => {
        try {
            const res = await fetcher({ token, category: 'neural-net', type: 'get-model-age' });
            if (!res.ok) throw new Error('Server error');
            const data = await res.json();
            if (data?.payload?.timestamp) setLastUpdated(data.payload.timestamp);
        } catch (err) {
            console.error(err);
        }
    };
    const handlePredict = async () => {
        if (!dnsHistory?.length) {
            setPredictions(['No DNS History']);
            return;
        }

        setPredictions(['Predicting...']);
        try {
            const res = await fetcher({ token, category: 'neural_net', type: 'predict', payload: dnsHistory });
            if (!res.ok) throw new Error('Server error');
            const data = await res.json();
            if (!data.success || !data.payload?.predictions) {
                console.error('Invalid response:', data);
                setPredictions([]);
                return;
            }
            setPredictions(data.payload.predictions);
        } catch (err) {
            console.error(err);
        }
    };

    const handleTrainModel = async () => {
        setTrainingStatus('Starting...');
        try {
            const res = await fetcher({ token, category: 'neural_net', type: 'train-new-model', timeout: 600 * 1000 });
            if (!res.ok) throw new Error('Failed to start training');

            const reader = res.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop();
                lines.forEach((line) => {
                    if (!line.trim()) return;
                    try {
                        const json = JSON.parse(line);
                        const payload = json.payload || {};
                        let extra = '';
                        if (payload.payload) {
                            const p = payload.payload;
                            if (p.avg_loss !== undefined) extra += ` Loss: ${p.avg_loss.toFixed(3)}`;
                            if (p.accuracy !== undefined) extra += ` Acc: ${p.accuracy.toFixed(3)}`;
                            if (p.training_time !== undefined) extra += ` Time: ${p.training_time.toFixed(2)}s`;
                        }
                        const status = payload.status || json.status || 'Training';
                        const progress = payload.progress !== undefined ? (payload.progress * 100).toFixed(1) : null;
                        setTrainingStatus(`${status}${progress ? ' ' + progress + '%' : ''}${extra}`);
                    } catch (err) {
                        console.error('JSON parse error:', err);
                    }
                });
            }

            setTrainingStatus('Training Complete');
        } catch (err) {
            console.error(err);
            setTrainingStatus('Training Failed');
        }
    };

    const handleClear = async () => {
        if (!confirm('Are you sure you want to clear DNS query history?')) return;
        await delay();
        try {
            const res = await fetcher({ token, category: 'dns-history', type: 'clear', payload: null });
            if (!res.ok) throw new Error('Server error');
            const jsonRes = await res.json();
            if (!jsonRes.success) throw new Error(jsonRes.error || 'Unknown error');
            setHistoryCleared(true);
        } catch {
            alert('Failed to clear DNS history');
        }
    };

    return (
        <div className="card">
            <div className="card-header">
                <h6>Actions</h6>
            </div>
            <div className="card-body p-0">
                <ActionRow label="Train Model" onClick={handleTrainModel} status={trainingStatus} />
                <ActionRow
                    label="Last Trained"
                    onClick={handleFetchTimestamp}
                    status={lastUpdated ? `${Math.floor(lastUpdated / 60)} min ago` : 'Not used yet'}
                />
                <ActionRow
                    label="Rate History"
                    onClick={handlePredict}
                    status={Array.isArray(predictions) ? `${predictions.length} Predictions` : 'Not used yet'}
                />
                <ActionRow
                    label="Clear History"
                    onClick={handleClear}
                    status={historyCleared ? `Cleared` : 'Not Cleared'}
                />
            </div>
        </div>
    );
}
window.Actions = Actions;
