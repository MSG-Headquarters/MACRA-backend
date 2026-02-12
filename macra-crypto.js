/**
 * MACRA Crypto - Backend Module
 * =============================
 * Mirrors the frontend macra-crypto.js encryption protocol.
 * Uses Node.js native crypto module with identical parameters:
 * - Key Derivation: PBKDF2 with SHA-256, 100,000 iterations
 * - Encryption: AES-256-GCM with 128-bit auth tag
 * - Salt: 16 bytes random
 * - IV: 12 bytes random
 * 
 * This is the "bridge" - same algorithm, same parameters,
 * same key derivation on both frontend and backend.
 */

const crypto = require('crypto');

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = 'sha256';
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16; // 128 bits
const ALGORITHM = 'aes-256-gcm';

/**
 * Derive encryption key from athlete code using PBKDF2
 * Matches frontend: PBKDF2, SHA-256, 100k iterations, 256-bit key
 */
function deriveKey(athleteCode, salt) {
    const normalizedCode = athleteCode.toUpperCase().replace(/\s/g, '');
    return crypto.pbkdf2Sync(
        Buffer.from(normalizedCode, 'utf8'),
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        PBKDF2_HASH
    );
}

/**
 * Encrypt data using athlete code
 * Output format matches frontend: { _encrypted, salt, iv, ciphertext, timestamp }
 */
function encrypt(data, athleteCode) {
    if (!athleteCode) return data;

    try {
        const salt = crypto.randomBytes(SALT_LENGTH);
        const iv = crypto.randomBytes(IV_LENGTH);
        const key = deriveKey(athleteCode, salt);
        const plaintext = JSON.stringify(data);

        const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
        const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();

        // Combine ciphertext + authTag (matches Web Crypto API behavior)
        const combined = Buffer.concat([encrypted, authTag]);

        return {
            _encrypted: true,
            salt: salt.toString('base64'),
            iv: iv.toString('base64'),
            ciphertext: combined.toString('base64'),
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Backend encryption error:', error);
        throw new Error('Failed to encrypt data');
    }
}

/**
 * Decrypt data encrypted by frontend (or backend)
 * Handles the { _encrypted, salt, iv, ciphertext } format
 */
function decrypt(payload, athleteCode) {
    if (!payload || !payload._encrypted) return payload;
    if (!athleteCode) throw new Error('Athlete code required for decryption');

    try {
        const salt = Buffer.from(payload.salt, 'base64');
        const iv = Buffer.from(payload.iv, 'base64');
        const combined = Buffer.from(payload.ciphertext, 'base64');

        // Web Crypto API appends auth tag to ciphertext
        const authTag = combined.slice(combined.length - AUTH_TAG_LENGTH);
        const ciphertext = combined.slice(0, combined.length - AUTH_TAG_LENGTH);

        const key = deriveKey(athleteCode, salt);

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return JSON.parse(decrypted.toString('utf8'));
    } catch (error) {
        console.error('Backend decryption error:', error);
        throw new Error('Failed to decrypt data - wrong athlete code?');
    }
}

/**
 * Check if a payload is encrypted
 */
function isEncrypted(payload) {
    return payload && payload._encrypted === true && payload.salt && payload.iv && payload.ciphertext;
}

module.exports = {
    encrypt,
    decrypt,
    deriveKey,
    isEncrypted,
    version: '2.1.0'
};
