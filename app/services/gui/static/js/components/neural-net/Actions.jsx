function Actions({ token, dnsHistory }) {
    const { useState } = React;
    const [trainingStatus, setTrainingStatus] = useState('Idle');
    const [lastUpdated, setLastUpdated] = useState('');
    const [predictionResult, setPredictionResult] = useState(null);
    const [domainHistory, setDomainHistory] = useState(dnsHistory);

    const ActionRow = ({ label, onClick, status }) => (
        <div className="d-flex justify-content-between align-items-center px-4 py-3 border-bottom">
            <button className="btn btn-primary btn-sm text-center" style={{ minWidth: '120px' }} onClick={onClick}>
                {label}
            </button>
            <span className="badge bg-secondary">{status}</span>
        </div>
    );

    const fetchData = async (body) => {
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });
            if (!res.ok) throw new Error(`Request failed: ${res.status}`);
            return await res.json();
        } catch (err) {
            console.error(err);
            return null;
        }
    };

    const handleFetchTimestamp = async () => {
        const data = await fetchData({ type: 'get-model-age' });
        if (data?.payload?.timestamp) {
            setLastUpdated(data.payload.timestamp);
        }
    };

    const handlePredict = async () => {
        if (!domainHistory?.length) {
            setPredictionResult('No domains to predict');
            return;
        }
        setPredictionResult('Predicting...');
        const data = await fetchData({ type: 'predict', payload: domainHistory });
        setPredictionResult(data?.payload?.predictions || 'No result');
    };

    const handleTrainModel = async () => {
        setTrainingStatus('Starting...');
        try {
            const res = await fetch('/api', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ type: 'train-new-model' }),
            });
            if (!res.ok) throw new Error('Failed to start training');
            const resReader = res.body.getReader();
            const decoder = new TextDecoder('utf-8');
            let resBuffer = '';
            while (true) {
                const { done, value } = await resReader.read();
                if (done) break;
                resBuffer += decoder.decode(value, { stream: true });
                const lines = resBuffer.split('\n');
                resBuffer = lines.pop();
                lines.forEach((line) => {
                    if (!line.trim()) return;
                    try {
                        const json = JSON.parse(line);
                        const payload = json.payload || {};
                        let extra = '';
                        if (payload.payload) {
                            const payloadPayload = payload.payload;
                            if (payloadPayload.avg_loss !== undefined)
                                extra += ` Loss: ${payloadPayload.avg_loss.toFixed(3)}`;
                            if (payloadPayload.accuracy !== undefined)
                                extra += ` Acc: ${payloadPayload.accuracy.toFixed(3)}`;
                            if (payloadPayload.training_time !== undefined)
                                extra += ` Time: ${payloadPayload.training_time.toFixed(2)}s`;
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

    return (
        <div className="mb-4">
            <div className="card w-100">
                <div className="card-header fw-bold text-uppercase">Actions Dashboard</div>
                <div className="card-body p-0">
                    <ActionRow label="Train" onClick={handleTrainModel} status={trainingStatus} />
                    <ActionRow
                        label="Trained at"
                        onClick={handleFetchTimestamp}
                        status={lastUpdated ? `${Math.floor(lastUpdated / 60)} min ago` : 'No timestamp yet'}
                    />
                    <ActionRow
                        label="Predict"
                        onClick={handlePredict}
                        status={Array.isArray(predictionResult) ? predictionResult.length : 0 + ' Predictions'}
                    />
                </div>
            </div>
        </div>
    );
}

window.Actions = Actions;
