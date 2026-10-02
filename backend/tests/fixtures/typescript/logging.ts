// Sensitive credentials in log statement
export function logAuthToken(token: string): void {
    console.warn("Authorization token emitted for debugging:", token);
}
