// TEST DATA FIXTURE - CLEAN TYPESCRIPT PATTERNS

interface UserProfile {
    id: string;
    username: string;
}

function parseProfile(data: unknown): UserProfile | null {
    if (typeof data === "object" && data !== null && "id" in data && "username" in data) {
        const record = data as { id: unknown; username: unknown };
        if (typeof record.id === "string" && typeof record.username === "string") {
            return { id: record.id, username: record.username };
        }
    }
    return null;
}
