// Clean JS file with robust error handling and no hardcoded secrets

export function calculateMetrics(values) {
    if (!Array.isArray(values) || values.length === 0) {
        return { count: 0, sum: 0, mean: 0 };
    }
    const sum = values.reduce((acc, curr) => acc + curr, 0);
    return {
        count: values.length,
        sum: sum,
        mean: sum / values.length,
    };
}

export function formatGreeting(name) {
    const safeName = (name || "Guest").trim();
    return `Hello, ${safeName}!`;
}
