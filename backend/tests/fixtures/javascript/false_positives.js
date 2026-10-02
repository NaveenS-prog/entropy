// False-positive verification cases
import { z } from 'zod';

// 1. Intentional empty catch
export function testIgnoredError() {
    try {
        cleanupTempFiles();
    } catch (e) {
        // intentional cleanup ignore
    }
}

// 2. Catch with diagnostic logging before fallback
export function safeGetConfig() {
    try {
        return readRemoteConfig();
    } catch (err) {
        console.error("Config lookup failed:", err);
        return null;
    }
}

// 3. Schema validated input before sensitive sink
const UserQuerySchema = z.object({
    id: z.string().uuid(),
});

export async function handleValidatedSearch(req, res, db) {
    const validated = UserQuerySchema.parse(req.query);
    const result = await db.query(`SELECT * FROM users WHERE id = $1`, [validated.id]);
    res.json(result);
}

// 4. Benign config environment variable
export const PORT = process.env.PORT || 8080;
export const HOST = process.env.HOST || "0.0.0.0";

// 5. Benign log message
console.log("Server initialized successfully on port", PORT);

// 6. Dummy / placeholder secret
export const testApiKey = "placeholder_key";
