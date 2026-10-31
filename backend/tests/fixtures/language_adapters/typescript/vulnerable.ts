// TEST DATA FIXTURE - VULNERABLE TYPESCRIPT PATTERNS

interface UserRequest {
    body?: {
        user?: {
            id: string;
            role?: string;
        }
    }
}

// @ts-ignore
function handleRequest(req: UserRequest) {
    // Unsafe type assertion bypass (ENT-TS-001)
    const rawData = req.body as any;

    // Dangerous non-null assertion on request boundary (ENT-TS-003)
    const userId = req.body!.user!.id;

    return { rawData, userId };
}
