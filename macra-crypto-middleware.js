/**
 * MACRA Crypto Middleware
 * =======================
 * Express middleware that bridges frontend encryption with backend processing.
 * 
 * Usage:
 *   const { decryptRequest, encryptResponse } = require('./macra-crypto-middleware');
 *   
 *   // Auto-decrypt incoming encrypted payloads
 *   app.post('/api/v2/workout/exercise', authenticateToken, decryptRequest, async (req, res) => {
 *       // req.body is now decrypted - use normally
 *       const { session_id, weight, reps } = req.body;
 *       // ...
 *       // Encrypt response before sending
 *       res.json(encryptResponse(responseData, req.athleteCode));
 *   });
 */

const macraCrypto = require('./macra-crypto');

// Cache athlete codes to avoid repeated DB lookups (TTL: 5 min)
const athleteCodeCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

/**
 * Middleware: Decrypt incoming request body if encrypted
 * Must run AFTER authenticateToken (needs req.user.userId)
 * Looks up athlete code from users table, caches it, decrypts req.body
 */
function createDecryptMiddleware(supabase) {
    return async function decryptRequest(req, res, next) {
        try {
            // Skip if body is not encrypted
            if (!macraCrypto.isEncrypted(req.body)) {
                return next();
            }

            // Get athlete code for this user
            const athleteCode = await getAthleteCode(req.user.userId, supabase);
            if (!athleteCode) {
                console.error('No athlete code found for user:', req.user.userId);
                return res.status(400).json({ error: 'Athlete code not found - cannot decrypt' });
            }

            // Store on request for response encryption
            req.athleteCode = athleteCode;

            // Decrypt the body
            const decrypted = macraCrypto.decrypt(req.body, athleteCode);
            req.body = decrypted;
            req._wasEncrypted = true;

            console.log(`🔓 Decrypted request for ${req.path}`);
            next();
        } catch (error) {
            console.error('Decrypt middleware error:', error.message);
            return res.status(400).json({ error: 'Failed to decrypt request body' });
        }
    };
}

/**
 * Encrypt response data if the request was encrypted
 * Call this in your route handler before res.json()
 */
function encryptResponse(data, athleteCode) {
    if (!athleteCode) return data;
    try {
        return macraCrypto.encrypt(data, athleteCode);
    } catch (error) {
        console.error('Response encryption error:', error);
        return data; // Fallback to unencrypted
    }
}

/**
 * Get athlete code for a user (with caching)
 */
async function getAthleteCode(userId, supabase) {
    // Check cache
    const cached = athleteCodeCache.get(userId);
    if (cached && Date.now() - cached.time < CACHE_TTL) {
        return cached.code;
    }

    // Lookup from database
    const { data } = await supabase
        .from('users')
        .select('athlete_code')
        .eq('id', userId)
        .single();

    if (data?.athlete_code) {
        athleteCodeCache.set(userId, { code: data.athlete_code, time: Date.now() });
        return data.athlete_code;
    }

    return null;
}

module.exports = { createDecryptMiddleware, encryptResponse };
