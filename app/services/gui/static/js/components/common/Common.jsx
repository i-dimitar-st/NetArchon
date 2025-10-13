function LoadingOverlay({ visible }) {
    if (!visible) return null;
    return <div className="loading-overlay">Loading...</div>;
}
window.LoadingOverlay = LoadingOverlay;
