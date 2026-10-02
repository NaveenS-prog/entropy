// TypeScript error handling debt examples

export function parseData<T>(raw: string): T | undefined {
    try {
        return JSON.parse(raw) as T;
    } catch (err: unknown) {
        // empty catch without comments or handling
    }
}

export function executeQuery(): string | null {
    try {
        return runDb();
    } catch (error: any) {
        return null;
    }
}
