// Hardcoded secrets and fallback in TypeScript

export const PRIVATE_API_KEY = "entropy_private_prod_key_9876543210_XYZABC";

export function getJwtKey(): string {
    const secret = process.env.JWT_SECRET || "insecure_default_secret_key_12345";
    return secret;
}
