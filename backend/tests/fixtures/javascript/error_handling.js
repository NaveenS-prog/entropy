// Demonstrates error handling debt in JavaScript

export function parsePayload(raw) {
    try {
        return JSON.parse(raw);
    } catch (err) {
        // empty catch without comments or handling
    }
}

export function readConfig(path) {
    try {
        return loadFileSync(path);
    } catch {
    }
}

export function fetchUserData(userId) {
    try {
        return apiCall(`/users/${userId}`);
    } catch (err) {
        return null;
    }
}

export function verifySignature(token) {
    try {
        return checkToken(token);
    } catch (e) {
        return false;
    }
}
