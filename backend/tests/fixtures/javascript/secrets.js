// Demonstrates hardcoded secrets and insecure fallbacks in JavaScript

export const API_KEY = "ENTROPY_STATIC_SECRET_KEY_1234567890_XYZ";
export const JWT_SECRET = "super_secret_production_key_12345";

export function getDatabasePassword() {
    const dbPassword = process.env.DATABASE_PASSWORD || "fallback_db_password_12345";
    return dbPassword;
}
