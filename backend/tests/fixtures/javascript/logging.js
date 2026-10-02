// Demonstrates sensitive information logged via console/logger

export function handleLogin(req) {
    const { username, password } = req.body;
    console.log("User login attempt with password:", password);
    logger.info("Session token created:", req.headers.authorization);
    return { ok: true };
}
