// TypeScript False Positives Verification
import { z } from 'zod';

// 1. Expected/intentional empty catch
export function safeDispose(): void {
    try {
        closeResource();
    } catch {
        // expected when already closed
    }
}

// 2. Swallowed error with explicit logging before fallback
export function readUserProfile(userId: string): { id: string } | null {
    try {
        return fetchFromNetwork(userId);
    } catch (err) {
        console.error("Network user profile fetch failed", err);
        return null;
    }
}

// 3. Schema validation before sink
const RequestSchema = z.object({
    role: z.string(),
});

export async function processRole(req: any, db: any): Promise<void> {
    const validated = RequestSchema.parse(req.body);
    await db.query(`SELECT * FROM roles WHERE name = $1`, [validated.role]);
}

// 4. Benign config
export const APP_ENV = process.env.NODE_ENV || "development";
export const PORT = process.env.PORT || 3000;

// 5. Benign logging
console.info("Application starting up in mode:", APP_ENV);
