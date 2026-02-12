require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createDecryptMiddleware, encryptResponse } = require('./macra-crypto-middleware');

const app = express();

const PORT = process.env.PORT || 3000;

// Initialize Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// Create crypto middleware instance
const decryptRequest = createDecryptMiddleware(supabase);

// Initialize Anthropic
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// Security middleware
app.use(helmet());

// CORS - allow frontend domains
app.use(cors({
    origin: [
        'https://macra.umbrassi.com',
        'https://macra.pages.dev',
        'http://localhost:5173',
        'http://localhost:3001',
        'http://localhost:3000'
    ],
    credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));

// Trust proxy (Railway runs behind proxy)
app.set('trust proxy', 1);

// Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    message: { error: 'Too many requests, please try again later' }
});
app.use(globalLimiter);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'macra-secret-key-change-in-production';

// ═══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    try {
        // Verify token with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = { userId: user.id, email: user.email };
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token verification failed' });
    }
}

// ═══════════════════════════════════════════════════════════════
// NUTRITION LOOKUP SYSTEM (USDA + NIH DSLD + Cache)
// ═══════════════════════════════════════════════════════════════

// Normalize query for cache key
function normalizeQuery(input) {
    return input.toLowerCase().trim().replace(/\s+/g, ' ');
}

// Check cache first
async function checkNutritionCache(input) {
    const queryKey = normalizeQuery(input);
    try {
        const { data, error } = await supabase
            .from('nutrition_cache')
            .select('*')
            .eq('query_key', queryKey)
            .single();
        
        if (data && !error) {
            // Increment hit count
            await supabase
                .from('nutrition_cache')
                .update({ hit_count: data.hit_count + 1, updated_at: new Date().toISOString() })
                .eq('id', data.id);
            
            console.log('Cache HIT for:', input);
            return data;
        }
    } catch (e) {
        // No cache hit
    }
    console.log('Cache MISS for:', input);
    return null;
}

// Save to cache
async function saveToNutritionCache(input, category, source, sourceId, nutritionData, micronutrients) {
    const queryKey = normalizeQuery(input);
    try {
        await supabase
            .from('nutrition_cache')
            .upsert({
                query_key: queryKey,
                input_text: input,
                category,
                source,
                source_id: sourceId,
                nutrition_data: nutritionData,
                micronutrients: micronutrients || {},
                updated_at: new Date().toISOString()
            }, { onConflict: 'query_key' });
        console.log('Cached:', input);
    } catch (e) {
        console.error('Cache save error:', e.message);
    }
}

// Search USDA for whole foods
async function searchUSDA(query) {
    console.log('USDA lookup for:', query);
    if (!process.env.USDA_API_KEY) return null;
    
    try {
        const response = await fetch(
            `https://api.nal.usda.gov/fdc/v1/foods/search?api_key=${process.env.USDA_API_KEY}&query=${encodeURIComponent(query)}&pageSize=3&dataType=Foundation,SR%20Legacy`
        );
        if (!response.ok) return null;
        
        const data = await response.json();
        if (!data.foods || data.foods.length === 0) return null;
        
        const food = data.foods[0];
        const nutrients = food.foodNutrients || [];
        const find = (name) => {
            const n = nutrients.find(n => (n.nutrientName || '').toLowerCase().includes(name.toLowerCase()));
            return n?.value || 0;
        };
        
        return {
            source: 'usda',
            sourceId: food.fdcId?.toString(),
            name: food.description,
            nutrition: {
                calories: Math.round(find('energy')),
                protein: Math.round(find('protein')),
                carbs: Math.round(find('carbohydrate')),
                fat: Math.round(find('total lipid') || find('fat')),
                fiber: Math.round(find('fiber')),
                sugar: Math.round(find('sugar')),
                sodium: Math.round(find('sodium'))
            },
            micronutrients: {
                vitaminA: Math.round(find('vitamin a')),
                vitaminC: Math.round(find('ascorbic acid') || find('vitamin c')),
                vitaminD: Math.round(find('vitamin d')),
                vitaminE: Math.round(find('vitamin e')),
                vitaminK: Math.round(find('vitamin k')),
                vitaminB6: parseFloat(find('vitamin b-6').toFixed(2)),
                vitaminB12: parseFloat(find('vitamin b-12').toFixed(2)),
                thiamin: parseFloat(find('thiamin').toFixed(2)),
                riboflavin: parseFloat(find('riboflavin').toFixed(2)),
                niacin: Math.round(find('niacin')),
                folate: Math.round(find('folate')),
                calcium: Math.round(find('calcium')),
                iron: parseFloat(find('iron').toFixed(1)),
                magnesium: Math.round(find('magnesium')),
                zinc: parseFloat(find('zinc').toFixed(1)),
                potassium: Math.round(find('potassium')),
                phosphorus: Math.round(find('phosphorus'))
            }
        };
    } catch (error) {
        console.error('USDA error:', error.message);
        return null;
    }
}

// Search NIH DSLD for supplements
async function searchNIHDSLD(query) {
    console.log('NIH DSLD lookup for:', query);
    
    try {
        // Use search-filter endpoint - searches across all label fields
        const searchUrl = `https://api.ods.od.nih.gov/dsld/v9/search-filter?q=${encodeURIComponent(query)}&size=5`;
        console.log('NIH DSLD URL:', searchUrl);
        
        const searchResponse = await fetch(searchUrl);
        
        if (!searchResponse.ok) {
            console.log('NIH DSLD search failed:', searchResponse.status);
            return null;
        }
        
        const searchData = await searchResponse.json();
        
        if (!searchData.hits || searchData.hits.length === 0) {
            console.log('NIH DSLD: No products found');
            return null;
        }
        
        // Get the first matching product's ID from _source
        const firstHit = searchData.hits[0];
        const productId = firstHit._id || firstHit._source?.id;
        const productName = firstHit._source?.fullName || query;
        const brandName = firstHit._source?.brandName;
        
        console.log('NIH DSLD found:', productName, '- ID:', productId);
        
        // Get the full label with ingredients
        const labelUrl = `https://api.ods.od.nih.gov/dsld/v9/label/${productId}`;
        const labelResponse = await fetch(labelUrl);
        
        if (!labelResponse.ok) {
            console.log('NIH DSLD label fetch failed:', labelResponse.status);
            return null;
        }
        
        const labelData = await labelResponse.json();
        
        // Extract nutrition from ingredientRows
        const ingredients = labelData.ingredientRows || [];
        const servingSize = labelData.servingSizes?.[0];
        const servingSizeText = servingSize ? `${servingSize.minQuantity} ${servingSize.unit}` : '1 serving';
        
        // Build micronutrients from ingredients
        const micronutrients = {};
        const nutritionMap = {
            'vitamin a': 'vitaminA',
            'vitamin c': 'vitaminC',
            'ascorbic acid': 'vitaminC',
            'vitamin d': 'vitaminD',
            'cholecalciferol': 'vitaminD',
            'vitamin e': 'vitaminE',
            'vitamin k': 'vitaminK',
            'vitamin b-6': 'vitaminB6',
            'vitamin b6': 'vitaminB6',
            'pyridoxine': 'vitaminB6',
            'vitamin b-12': 'vitaminB12',
            'vitamin b12': 'vitaminB12',
            'cobalamin': 'vitaminB12',
            'cyanocobalamin': 'vitaminB12',
            'thiamin': 'thiamin',
            'thiamine': 'thiamin',
            'vitamin b-1': 'thiamin',
            'vitamin b1': 'thiamin',
            'riboflavin': 'riboflavin',
            'vitamin b-2': 'riboflavin',
            'vitamin b2': 'riboflavin',
            'niacin': 'niacin',
            'vitamin b-3': 'niacin',
            'vitamin b3': 'niacin',
            'folate': 'folate',
            'folic acid': 'folate',
            'biotin': 'biotin',
            'pantothenic acid': 'pantothenicAcid',
            'calcium': 'calcium',
            'iron': 'iron',
            'magnesium': 'magnesium',
            'zinc': 'zinc',
            'selenium': 'selenium',
            'copper': 'copper',
            'manganese': 'manganese',
            'chromium': 'chromium',
            'molybdenum': 'molybdenum',
            'potassium': 'potassium',
            'sodium': 'sodium',
            'phosphorus': 'phosphorus',
            'iodine': 'iodine',
            'caffeine': 'caffeine',
            'creatine': 'creatine',
            'beta-alanine': 'betaAlanine',
            'citrulline': 'citrulline',
            'l-citrulline': 'citrulline',
            'arginine': 'arginine',
            'l-arginine': 'arginine',
            'taurine': 'taurine',
            'carnitine': 'carnitine',
            'l-carnitine': 'carnitine'
        };
        
        for (const ingredient of ingredients) {
            const name = (ingredient.name || '').toLowerCase();
            const quantity = ingredient.quantity?.[0];
            const amount = quantity?.quantity || 0;
            const unit = quantity?.unit || '';
            
            for (const [key, nutrientKey] of Object.entries(nutritionMap)) {
                if (name.includes(key)) {
                    micronutrients[nutrientKey] = {
                        amount: amount,
                        unit: unit
                    };
                    break;
                }
            }
        }
        
        console.log('NIH DSLD extracted', Object.keys(micronutrients).length, 'nutrients');
        
        return {
            source: 'nih_dsld',
            sourceId: productId.toString(),
            name: labelData.fullName || productName,
            brand: labelData.brandName || brandName,
            servingSize: servingSizeText,
            nutrition: {
                calories: 0,
                protein: 0,
                carbs: 0,
                fat: 0
            },
            micronutrients: micronutrients
        };
    } catch (error) {
        console.error('NIH DSLD error:', error.message);
        return null;
    }
}
// AI classification: is this food or supplement?
async function classifyInput(input) {
    try {
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 50,
            messages: [{ 
                role: 'user', 
                content: `Classify this as either "food" or "supplement". Only respond with one word.
                
Input: "${input}"

Guidelines:
- "food" = whole foods, meals, ingredients, restaurant items, home-cooked dishes
- "supplement" = vitamins, protein powders, pre-workouts, capsules, tablets, branded fitness products

Response (one word only):` 
            }]
        });
        
        const classification = message.content[0].text.toLowerCase().trim();
        console.log('AI classified as:', classification);
        return classification.includes('supplement') ? 'supplement' : 'food';
    } catch (error) {
        console.error('Classification error:', error.message);
        return 'food'; // Default to food
    }
}

// Web search fallback for supplements not in NIH DSLD
async function searchSupplementWeb(query) {
    console.log('Web search fallback for:', query);
    
    try {
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1500,
            tools: [{
                type: 'web_search_20250305',
                name: 'web_search'
            }],
            messages: [{
                role: 'user',
                content: `Find the supplement facts label for "${query}". 
Return ONLY a JSON object with the nutrition information. Search the official brand website.

Return format:
{
    "name": "Product Name",
    "brand": "Brand Name", 
    "servingSize": "1 scoop (10g)",
    "calories": 0,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "micronutrients": {
        "vitaminC": {"amount": 100, "unit": "mg"},
        "caffeine": {"amount": 200, "unit": "mg"}
    }
}

Only include micronutrients that are actually on the label. Return ONLY valid JSON, no other text.`
            }]
        });
        
        // Extract JSON from response
        let fullText = '';
        for (const block of message.content) {
            if (block.type === 'text') {
                fullText += block.text;
            }
        }
        
        // Try to parse JSON
        const jsonMatch = fullText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            const data = JSON.parse(jsonMatch[0]);
            return {
                source: 'web_search',
                sourceId: null,
                name: data.name || query,
                brand: data.brand,
                servingSize: data.servingSize,
                nutrition: {
                    calories: data.calories || 0,
                    protein: data.protein || 0,
                    carbs: data.carbs || 0,
                    fat: data.fat || 0
                },
                micronutrients: data.micronutrients || {}
            };
        }
    } catch (error) {
        console.error('Web search error:', error.message);
    }
    return null;
}

// Main nutrition lookup function
async function lookupNutrition(input) {
    // 1. Check cache first
    const cached = await checkNutritionCache(input);
    if (cached) {
        return {
            source: cached.source,
            sourceId: cached.source_id,
            category: cached.category,
            nutrition: cached.nutrition_data,
            micronutrients: cached.micronutrients,
            fromCache: true
        };
    }
    
    // 2. Classify input
    const category = await classifyInput(input);
    
    let result = null;
    
    if (category === 'supplement') {
        // 3a. Try NIH DSLD first for supplements
        result = await searchNIHDSLD(input);
        
        // 3b. Fall back to web search if not found
        if (!result) {
            result = await searchSupplementWeb(input);
        }
    } else {
        // 3c. Use USDA for whole foods
        result = await searchUSDA(input);
    }
    
    // 4. Cache the result if found
    if (result) {
        await saveToNutritionCache(
            input,
            category,
            result.source,
            result.sourceId,
            result.nutrition,
            result.micronutrients
        );
    }
    
    return result ? { ...result, category, fromCache: false } : null;
}
// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════

app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'macra-backend', version: '2.1.0', timestamp: new Date().toISOString() });
});

// Debug test endpoint
app.get('/test-auth', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    console.log('Test auth hit, token:', token?.substring(0, 30) + '...');
    if (!token) return res.json({ error: 'No token provided' });
    try {
        const { data, error } = await supabase.auth.getUser(token);
        console.log('Supabase response:', JSON.stringify({ user: data?.user?.email, error: error?.message }));
        res.json({ user: data?.user?.email, error: error?.message });
    } catch (e) {
        console.log('Exception:', e.message);
        res.json({ exception: e.message });
    }
});

// ═══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        // Create user with Supabase Auth
        const { data, error: authError } = await supabase.auth.signUp({
            email: email.toLowerCase(),
            password: password,
            options: {
                data: { name: name || 'Athlete' }
            }
        });

        if (authError) {
            if (authError.message.includes('already registered')) {
                return res.status(400).json({ error: 'Email already registered' });
            }
            throw authError;
        }

        // Create the users row with the auth user's ID
        const athleteCode = 'MACRA-' + crypto.randomBytes(4).toString('hex').toUpperCase();

        const { error: userError } = await supabase.from('users').upsert({
            id: data.user.id,
            email: email.toLowerCase(),
            name: name || 'Athlete',
            athlete_code: athleteCode,
            is_public: true,
            tier: 'free',
            total_workouts: 0,
            current_streak: 0
        }, { onConflict: 'id' });

        if (userError) {
            console.error('Failed to create user record:', userError);
            // Don't fail signup, but log the issue
        }

        console.log('New user created:', email, athleteCode);
        res.json({ success: true, message: 'Account created', athleteCode });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        
        // Use Supabase Auth for login
        const { data, error } = await supabase.auth.signInWithPassword({
            email: email.toLowerCase(),
            password: password
        });
        
        if (error || !data.user) {
            console.log('Supabase auth error:', error?.message);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Get user profile from users table
        const { data: profile, error: profileError } = await supabase.from('users').select('*').eq('id', data.user.id).single();
        
        if (profileError) {
            console.log('Profile lookup by ID failed:', profileError.message, '- trying email fallback');
        }
        
        // Fallback: lookup by email if ID lookup failed
        let userProfile = profile;
        if (!userProfile) {
            const { data: emailProfile } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).single();
            userProfile = emailProfile;
            // If found by email but ID doesn't match, update the ID
            if (userProfile && userProfile.id !== data.user.id) {
                console.log('Updating user ID from', userProfile.id, 'to', data.user.id);
                await supabase.from('users').update({ id: data.user.id }).eq('email', email.toLowerCase());
            }
        }
        
        res.json({
            token: data.session.access_token,
            refreshToken: data.session.refresh_token,
            user: {
                id: data.user.id,
                email: data.user.email,
                name: userProfile?.name || 'Athlete',
                athleteCode: userProfile?.athlete_code || 'MACRA-0000',
                tier: userProfile?.tier || 'free'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
        
        const decoded = jwt.verify(refreshToken, JWT_SECRET);
        const { data: user } = await supabase.from('users').select('*').eq('id', decoded.userId).single();
        if (!user) return res.status(401).json({ error: 'User not found' });
        
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        const newRefreshToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ token, refreshToken: newRefreshToken });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.json({ success: true });
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });

        // Use Supabase Auth's built-in password reset
        const { error } = await supabase.auth.resetPasswordForEmail(email.toLowerCase(), {
            redirectTo: 'https://macra.umbrassi.com/reset-password'
        });

        if (error) {
            console.error('Password reset error:', error);
        }

        // Always return success (don't reveal if email exists)
        res.json({ success: true, message: 'If account exists, reset email sent' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new password required' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters' });
        }

        // Verify current password by attempting to sign in
        const { data: profile } = await supabase.from('users').select('email').eq('id', req.user.userId).single();
        if (!profile) return res.status(404).json({ error: 'User not found' });

        const { error: signInError } = await supabase.auth.signInWithPassword({
            email: profile.email,
            password: currentPassword
        });

        if (signInError) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Update password
        const { error: updateError } = await supabase.auth.admin.updateUserById(req.user.userId, {
            password: newPassword
        });

        if (updateError) throw updateError;

        console.log('Password changed for:', profile.email);
        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Admin: Reset a user's password directly (protected by admin secret)
app.post('/api/admin/reset-password', async (req, res) => {
    try {
        const { email, newPassword, adminKey } = req.body;
        if (adminKey !== process.env.ADMIN_KEY) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        if (!email || !newPassword) {
            return res.status(400).json({ error: 'Email and new password required' });
        }

        // Find user by email
        const { data: users } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
        if (!users) return res.status(404).json({ error: 'User not found' });

        // Update password via Supabase Admin API
        const { error } = await supabase.auth.admin.updateUserById(users.id, {
            password: newPassword
        });

        if (error) throw error;
        console.log('Password reset for:', email);
        res.json({ success: true, message: `Password reset for ${email}` });
    } catch (error) {
        console.error('Admin reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Get list of users the authenticated user is following
app.get('/api/users/following', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Get current user's following list
        const { data: userData } = await supabase
            .from('users')
            .select('following')
            .eq('id', userId)
            .single();

        const followingIds = userData?.following || [];

        if (followingIds.length === 0) {
            return res.json({ following: [] });
        }

        // Fetch profiles of followed users
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, athlete_code, bio, total_workouts, current_streak, is_public')
            .in('id', followingIds);

        if (error) throw error;

        const following = (users || []).map(u => ({
            id: u.id,
            name: u.name || 'Athlete',
            athleteCode: u.athlete_code,
            bio: u.bio || '',
            avatar: (u.name || 'A')[0].toUpperCase(),
            stats: {
                workouts: u.total_workouts || 0,
                streak: u.current_streak || 0
            }
        }));

        res.json({ following });
    } catch (error) {
        console.error('Get following error:', error);
        res.status(500).json({ error: 'Failed to get following list' });
    }
});


// ═══════════════════════════════════════════════════════════════
// USER DISCOVERY SYSTEM
// ═══════════════════════════════════════════════════════════════
// Search users by name
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const query = req.query.q;
        if (!query || query.length < 2) {
            return res.status(400).json({ error: 'Search query must be at least 2 characters' });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, athlete_code, bio, total_workouts, current_streak, is_public')
            .eq('is_public', true)
            .ilike('name', `%${query}%`)
            .neq('id', req.user.userId)
            .limit(10);

        if (error) throw error;

        const formatted = (users || []).map(u => ({
            id: u.id,
            name: u.name || 'Athlete',
            athleteCode: u.athlete_code,
            bio: u.bio || '',
            avatar: (u.name || 'A')[0].toUpperCase(),
            stats: {
                workouts: u.total_workouts || 0,
                streak: u.current_streak || 0
            }
        }));

        res.json({ users: formatted });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Discover random public users to follow
app.get('/api/users/discover', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const limit = parseInt(req.query.limit) || 3;
        
        // Get user's current following list
        const { data: userData } = await supabase
            .from('users')
            .select('following')
            .eq('id', userId)
            .single();
        
        const following = userData?.following || [];
        
        // Get random public users excluding self and already following
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, athlete_code, bio, total_workouts, current_streak, is_public')
            .eq('is_public', true)
            .neq('id', userId)
            .limit(20); // Get more than needed so we can filter and randomize
        
        if (error) throw error;
        
        // Filter out already following and randomize
        const notFollowing = (users || []).filter(u => !following.includes(u.id));
        const shuffled = notFollowing.sort(() => Math.random() - 0.5);
        const selected = shuffled.slice(0, limit);
        
        // Format response
        const formatted = selected.map(u => ({
            id: u.id,
            name: u.name || 'Athlete',
            athleteCode: u.athlete_code,
            bio: u.bio || '',
            avatar: (u.name || 'A')[0].toUpperCase(),
            stats: {
                workouts: u.total_workouts || 0,
                streak: u.current_streak || 0
            },
            isPublic: u.is_public
        }));
        
        res.json({ users: formatted });
    } catch (error) {
        console.error('Discover error:', error);
        res.status(500).json({ error: 'Failed to discover users' });
    }
});

// Get public profile by athlete code
app.get('/api/users/profile/:athleteCode', authenticateToken, async (req, res) => {
    try {
        const { athleteCode } = req.params;
        
        const { data: user, error } = await supabase
            .from('users')
            .select('id, name, athlete_code, bio, total_workouts, current_streak, is_public, created_at')
            .eq('athlete_code', athleteCode)
            .single();
        
        if (error || !user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // If private, return limited info
        if (!user.is_public) {
            return res.json({
                profile: {
                    athleteCode: user.athlete_code,
                    name: user.name || 'Athlete',
                    avatar: (user.name || 'A')[0].toUpperCase(),
                    isPublic: false,
                    message: 'This profile is private'
                }
            });
        }
        
        // Return full public profile
        res.json({
            profile: {
                id: user.id,
                athleteCode: user.athlete_code,
                name: user.name || 'Athlete',
                bio: user.bio || '',
                avatar: (user.name || 'A')[0].toUpperCase(),
                stats: {
                    workouts: user.total_workouts || 0,
                    streak: user.current_streak || 0
                },
                isPublic: true,
                memberSince: user.created_at
            }
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Follow a user by athlete code
app.post('/api/users/follow', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { athleteCode } = req.body;
        
        if (!athleteCode) {
            return res.status(400).json({ error: 'Athlete code required' });
        }
        
        // Find the user to follow
        const { data: targetUser, error: findError } = await supabase
            .from('users')
            .select('id, name, athlete_code')
            .eq('athlete_code', athleteCode)
            .single();
        
        if (findError || !targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (targetUser.id === userId) {
            return res.status(400).json({ error: "You can't follow yourself" });
        }
        
        // Get current following list
        const { data: userData } = await supabase
            .from('users')
            .select('following')
            .eq('id', userId)
            .single();
        
        const following = userData?.following || [];
        
        if (following.includes(targetUser.id)) {
            return res.status(400).json({ error: 'Already following this user' });
        }
        
        // Add to following list
        following.push(targetUser.id);
        
        const { error: updateError } = await supabase
            .from('users')
            .update({ following })
            .eq('id', userId);
        
        if (updateError) throw updateError;
        
        res.json({ 
            success: true, 
            message: `Now following ${targetUser.name}`,
            user: {
                id: targetUser.id,
                name: targetUser.name,
                athleteCode: targetUser.athlete_code
            }
        });
    } catch (error) {
        console.error('Follow error:', error);
        res.status(500).json({ error: 'Failed to follow user' });
    }
});

// Unfollow a user
app.post('/api/users/unfollow', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { targetUserId } = req.body;
        
        if (!targetUserId) {
            return res.status(400).json({ error: 'Target user ID required' });
        }
        
        // Get current following list
        const { data: userData } = await supabase
            .from('users')
            .select('following')
            .eq('id', userId)
            .single();
        
        let following = userData?.following || [];
        following = following.filter(id => id !== targetUserId);
        
        const { error: updateError } = await supabase
            .from('users')
            .update({ following })
            .eq('id', userId);
        
        if (updateError) throw updateError;
        
        res.json({ success: true, message: 'Unfollowed successfully' });
    } catch (error) {
        console.error('Unfollow error:', error);
        res.status(500).json({ error: 'Failed to unfollow user' });
    }
});

// Update profile visibility
app.post('/api/users/privacy', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { isPublic } = req.body;
        
        const { error } = await supabase
            .from('users')
            .update({ is_public: isPublic })
            .eq('id', userId);
        
        if (error) throw error;
        
        res.json({ success: true, isPublic });
    } catch (error) {
        console.error('Privacy update error:', error);
        res.status(500).json({ error: 'Failed to update privacy' });
    }
});

// ═══════════════════════════════════════════════════════════════
// AI PARSING ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/api/ai/parse', authenticateToken, async (req, res) => {
    try {
        const { input } = req.body;
        if (!input) return res.status(400).json({ error: 'Input required' });

        // Check if this is a workout/cardio/weight input (not food)
        const isWorkout = input.toLowerCase().match(/bench|squat|deadlift|press|curl|row|pull|push|sets|reps|lbs|kg|\d+x\d+/);
        const isCardio = input.toLowerCase().match(/run|ran|walk|walked|bike|biked|swim|swam|cardio|miles|minutes|km/);
        const isWeight = input.toLowerCase().match(/^(weigh|weight|i weigh|weighed)\s*\d/i);

        // For workouts, cardio, weight - use simple AI parse (no nutrition lookup)
        if (isWorkout || isCardio || isWeight) {
            const today = new Date().toISOString();
            
            const message = await anthropic.messages.create({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 1024,
                messages: [{ role: 'user', content: `Parse this fitness input and return JSON only (no markdown):
Input: "${input}"
Today's date: ${today}

IMPORTANT: Check if the input contains a date reference (like "2/4/26", "Feb 4", "yesterday", "last Monday", "3 days ago"). If so, calculate the actual date and include it as "logDate" in ISO format.

Return one of these formats:
For workout: {"type":"workout","data":{"exercises":[{"name":"exercise name","weight":135,"reps":10,"setNumber":1,"category":"chest|back|shoulders|arms|legs|core"}]},"logDate":"2026-02-04T12:00:00.000Z"}
CRITICAL: Each LINE of input = ONE entry in exercises array. NEVER combine or sum reps. "bench 135x10" on 3 lines = 3 entries each with reps:10, NOT 1 entry with reps:30.
For cardio: {"type":"cardio","data":{"activity":"activity name","duration":0,"distance":0,"calories":0},"logDate":"2026-02-04T12:00:00.000Z"}
For weight: {"type":"weight","data":{"weight":0,"unit":"lbs"},"logDate":"2026-02-04T12:00:00.000Z"}

If NO date is mentioned in the input, set "logDate" to null.
Return ONLY valid JSON.` }]
            });

            const text = message.content[0].text;
            const result = JSON.parse(text.replace(/```json\n?|\n?```/g, '').trim());
            console.log('Parse result with date:', JSON.stringify(result));
            return res.json({ result });
        }

        // For food/supplements - use nutrition lookup system
        const nutritionData = await lookupNutrition(input);
        
        // Build context for AI
        let nutritionContext = '';
        if (nutritionData) {
            nutritionContext = `
Nutrition data found (source: ${nutritionData.source}, cached: ${nutritionData.fromCache}):
Name: ${nutritionData.name || input}
Category: ${nutritionData.category}
Calories: ${nutritionData.nutrition?.calories || 0}
Protein: ${nutritionData.nutrition?.protein || 0}g
Carbs: ${nutritionData.nutrition?.carbs || 0}g
Fat: ${nutritionData.nutrition?.fat || 0}g
Micronutrients: ${JSON.stringify(nutritionData.micronutrients || {})}

Use this data to provide accurate nutrition values.`;
        }

        const today = new Date().toISOString();
        
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1500,
            messages: [{ role: 'user', content: `Parse this food/supplement input and return JSON only (no markdown):
Input: "${input}"
Today's date: ${today}
${nutritionContext}

IMPORTANT: Check if the input contains a date reference (like "2/4/26", "Feb 4", "yesterday", "last Monday", "3 days ago"). If so, calculate the actual date and include it as "logDate" in ISO format.

Return this format:
{
    "type": "food",
    "data": {
        "items": [{
            "name": "item name",
            "calories": 0,
            "protein": 0,
            "carbs": 0,
            "fat": 0,
            "fiber": 0,
            "sugar": 0,
            "sodium": 0
        }],
        "totals": {
            "calories": 0,
            "protein": 0,
            "carbs": 0,
            "fat": 0
        },
        "micronutrients": {
            "vitaminA": 0,
            "vitaminC": 0,
            "vitaminD": 0,
            "vitaminB6": 0,
            "vitaminB12": 0,
            "calcium": 0,
            "iron": 0,
            "magnesium": 0,
            "zinc": 0,
            "potassium": 0,
            "caffeine": 0,
            "creatine": 0
        },
        "mealType": "breakfast|lunch|dinner|snack|supplement"
    },
    "source": "${nutritionData?.source || 'estimate'}",
    "cached": ${nutritionData?.fromCache || false},
    "logDate": null
}

IMPORTANT:
- Only include micronutrients with values > 0
- For micronutrients with amount/unit objects, convert to just the numeric amount
- Use the provided nutrition data for accuracy
- If a date is mentioned, set "logDate" to the ISO date string (e.g., "2026-02-04T12:00:00.000Z")
- If NO date is mentioned, set "logDate" to null
- Return ONLY valid JSON` }]
        });

        const text = message.content[0].text;
        const result = JSON.parse(text.replace(/```json\n?|\n?```/g, '').trim());
        
        console.log('Parse result:', JSON.stringify(result, null, 2));
        res.json({ result });
    } catch (error) {
        console.error('AI parse error:', error);
        res.status(500).json({ error: 'Failed to parse input' });
    }
});
app.post('/api/ai/photo', authenticateToken, async (req, res) => {
    try {
        const { image, mimeType } = req.body;
        if (!image) return res.status(400).json({ error: 'Image required' });
        
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1024,
            messages: [{
                role: 'user',
                content: [
                    { type: 'image', source: { type: 'base64', media_type: mimeType || 'image/jpeg', data: image } },
                    { type: 'text', text: `Analyze this food image. Return JSON only (no markdown):
{"type":"food","data":{"items":[{"name":"food","calories":0,"protein":0,"carbs":0,"fat":0}],"totals":{"calories":0,"protein":0,"carbs":0,"fat":0}}}
Be accurate with portions visible. Return ONLY valid JSON.` }
                ]
            }]
        });
        
        const text = message.content[0].text;
        const result = JSON.parse(text.replace(/```json\n?|\n?```/g, '').trim());
        res.json({ result });
    } catch (error) {
        console.error('Photo analysis error:', error);
        res.status(500).json({ error: 'Failed to analyze photo' });
    }
});

// ═══════════════════════════════════════════════════════════════
// USER DATA SYNC ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/api/user/sync', authenticateToken, async (req, res) => {
    try {
        const { activities, goals, profile_data, stats, prs, weightHistory } = req.body;
        
        const { error } = await supabase.from('user_data').upsert({
            user_id: req.user.userId,
            activities: activities || {},
            goals: goals || {},
            profile_data: profile_data || {},
            stats: stats || {},
            prs: prs || {},
            weight_history: weightHistory || [],
            updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });
        
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Sync error:', error);
        res.status(500).json({ error: 'Sync failed' });
    }
});

app.get('/api/user/data', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from('user_data').select('*').eq('user_id', req.user.userId).single();
        if (error && error.code !== 'PGRST116') throw error;
        
        res.json(data || { activities: {}, goals: {}, profile_data: {}, stats: {}, prs: {}, weightHistory: [] });
    } catch (error) {
        console.error('Get data error:', error);
        res.status(500).json({ error: 'Failed to get data' });
    }
});

// ═══════════════════════════════════════════════════════════════
// V2 WORKOUT SESSION ROUTES
// ═══════════════════════════════════════════════════════════════

app.get('/api/v2/workout/active', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('workout_sessions')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('status', 'active')
            .order('started_at', { ascending: false })
            .limit(1)
            .single();
        
        if (error && error.code !== 'PGRST116') throw error;
        if (data) {
            const { data: profile } = await supabase.from('users').select('athlete_code').eq('id', req.user.userId).single();
            if (profile?.athlete_code) {
                return res.json({ session: encryptResponse(data, profile.athlete_code) });
            }
        }
        res.json({ session: data || null });
    } catch (error) {
        console.error('Get active workout error:', error);
        res.status(500).json({ error: 'Failed to get active workout' });
    }
});

app.post('/api/v2/workout/start', authenticateToken, decryptRequest, async (req, res) => {
    try {
        const { workout_name } = req.body;
        
        // Check for existing active session
        const { data: existing } = await supabase
            .from('workout_sessions')
            .select('id')
            .eq('user_id', req.user.userId)
            .eq('status', 'active')
            .single();
        
        if (existing) {
            return res.status(400).json({ error: 'Active session exists', session_id: existing.id });
        }
        
        const { data, error } = await supabase
            .from('workout_sessions')
            .insert({
                user_id: req.user.userId,
                workout_name: workout_name || null,
                status: 'active',
                started_at: new Date().toISOString(),
                exercises: [],
                summary: { total_volume: 0, total_sets: 0, total_exercises: 0, muscle_groups: {} }
            })
            .select()
            .single();
        
        if (error) throw error;
        res.json({ session: req.athleteCode ? encryptResponse(data, req.athleteCode) : data });
    } catch (error) {
        console.error('Start workout error:', error);
        res.status(500).json({ error: 'Failed to start workout' });
    }
});

app.post('/api/v2/workout/exercise', authenticateToken, decryptRequest, async (req, res) => {
    try {
        const { session_id, exercise_name, original_input, weight, reps, sets, category } = req.body;
        
        const { data: session, error: fetchError } = await supabase
            .from('workout_sessions')
            .select('*')
            .eq('id', session_id)
            .eq('user_id', req.user.userId)
            .single();
        
        if (fetchError || !session) return res.status(404).json({ error: 'Session not found' });
        
        const exercises = session.exercises || [];
        const existingIndex = exercises.findIndex(e => e.name.toLowerCase() === exercise_name.toLowerCase());
        
        const newSet = {
            set_num: existingIndex >= 0 ? exercises[existingIndex].sets.length + 1 : 1,
            weight: weight || 0,
            reps: reps || 0,
            logged_at: new Date().toISOString()
        };
        
        if (existingIndex >= 0) {
            exercises[existingIndex].sets.push(newSet);
        } else {
            exercises.push({
                id: crypto.randomUUID(),
                name: exercise_name,
                category: category || 'other',
                sets: [newSet]
            });
        }
        
        // Update summary
        const summary = {
            total_exercises: exercises.length,
            total_sets: exercises.reduce((sum, e) => sum + e.sets.length, 0),
            total_volume: exercises.reduce((sum, e) => sum + e.sets.reduce((s, set) => s + (set.weight * set.reps), 0), 0),
            muscle_groups: {}
        };
        
        exercises.forEach(e => {
            const cat = e.category || 'other';
            summary.muscle_groups[cat] = (summary.muscle_groups[cat] || 0) + e.sets.length;
        });
        
        const { data: updated, error: updateError } = await supabase
            .from('workout_sessions')
            .update({ exercises, summary, updated_at: new Date().toISOString() })
            .eq('id', session_id)
            .select()
            .single();
        
        if (updateError) throw updateError;
        res.json({ session: req.athleteCode ? encryptResponse(updated, req.athleteCode) : updated });
    } catch (error) {
        console.error('Add exercise error:', error);
        res.status(500).json({ error: 'Failed to add exercise' });
    }
});

app.delete('/api/v2/workout/exercise', authenticateToken, decryptRequest, async (req, res) => {
    try {
        const { session_id, exercise_id, set_num } = req.body;
        
        const { data: session } = await supabase
            .from('workout_sessions')
            .select('*')
            .eq('id', session_id)
            .eq('user_id', req.user.userId)
            .single();
        
        if (!session) return res.status(404).json({ error: 'Session not found' });
        
        let exercises = session.exercises || [];
        
        if (set_num) {
            const ex = exercises.find(e => e.id === exercise_id);
            if (ex) {
                ex.sets = ex.sets.filter(s => s.set_num !== set_num);
                ex.sets.forEach((s, i) => s.set_num = i + 1);
                if (ex.sets.length === 0) exercises = exercises.filter(e => e.id !== exercise_id);
            }
        } else {
            exercises = exercises.filter(e => e.id !== exercise_id);
        }
        
        const summary = {
            total_exercises: exercises.length,
            total_sets: exercises.reduce((sum, e) => sum + e.sets.length, 0),
            total_volume: exercises.reduce((sum, e) => sum + e.sets.reduce((s, set) => s + (set.weight * set.reps), 0), 0),
            muscle_groups: {}
        };
        
        const { data: updated } = await supabase
            .from('workout_sessions')
            .update({ exercises, summary })
            .eq('id', session_id)
            .select()
            .single();
        
        res.json({ session: req.athleteCode ? encryptResponse(updated, req.athleteCode) : updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete' });
    }
});

app.post('/api/v2/workout/finalize', authenticateToken, decryptRequest, async (req, res) => {
    try {
        const { session_id, workout_name, notes } = req.body;
        
        const { data: session } = await supabase
            .from('workout_sessions')
            .select('*')
            .eq('id', session_id)
            .eq('user_id', req.user.userId)
            .single();
        
        if (!session) return res.status(404).json({ error: 'Session not found' });
        
        const duration = Math.round((Date.now() - new Date(session.started_at).getTime()) / 60000);
        
        const { data: updated } = await supabase
            .from('workout_sessions')
            .update({
                status: 'completed',
                workout_name: workout_name || session.workout_name || 'Workout',
                notes,
                ended_at: new Date().toISOString(),
                summary: { ...session.summary, duration_minutes: duration }
            })
            .eq('id', session_id)
            .select()
            .single();
        
        res.json({ session: req.athleteCode ? encryptResponse(updated, req.athleteCode) : updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to finalize' });
    }
});

app.post('/api/v2/workout/cancel', authenticateToken, decryptRequest, async (req, res) => {
    try {
        const { session_id } = req.body;
        
        // Delete the workout session
        await supabase
            .from('workout_sessions')
            .delete()
            .eq('id', session_id)
            .eq('user_id', req.user.userId)
            .eq('status', 'active');
        
        res.json({ success: true, message: 'Workout cancelled' });
    } catch (error) {
        console.error('Cancel workout error:', error);
        res.status(500).json({ error: 'Failed to cancel workout' });
    }
});

// ═══════════════════════════════════════════════════════════════
// V2 NUTRITION ROUTES
// ═══════════════════════════════════════════════════════════════

app.get('/api/v2/nutrition/today', authenticateToken, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        const { data, error } = await supabase
            .from('nutrition_days')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('date', today)
            .single();
        
        if (error && error.code !== 'PGRST116') throw error;
        
        if (!data) {
            // Create today's nutrition record
            const { data: newDay } = await supabase
                .from('nutrition_days')
                .insert({
                    user_id: req.user.userId,
                    date: today,
                    meals: {},
                    totals: { calories: 0, protein: 0, carbs: 0, fat: 0 },
                    water: { target_oz: 128, logged_oz: 0 }
                })
                .select()
                .single();
            
            return res.json({ nutrition_day: newDay });
        }
        
        res.json({ nutrition_day: data });
    } catch (error) {
        console.error('Get nutrition error:', error);
        res.status(500).json({ error: 'Failed to get nutrition' });
    }
});

app.post('/api/v2/nutrition/food', authenticateToken, async (req, res) => {
    try {
        const { name, calories, protein, carbs, fat, meal_type, time } = req.body;
        const today = new Date().toISOString().split('T')[0];
        
        // Determine meal type based on time if not provided
        let mealCategory = meal_type;
        if (!mealCategory) {
            const hour = new Date(time || Date.now()).getHours();
            if (hour < 10) mealCategory = 'breakfast';
            else if (hour < 12) mealCategory = 'snack_am';
            else if (hour < 14) mealCategory = 'lunch';
            else if (hour < 17) mealCategory = 'snack_pm';
            else mealCategory = 'dinner';
        }
        
        // Get or create today's record
        let { data: day } = await supabase
            .from('nutrition_days')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('date', today)
            .single();
        
        if (!day) {
            const { data: newDay } = await supabase
                .from('nutrition_days')
                .insert({
                    user_id: req.user.userId,
                    date: today,
                    meals: {},
                    totals: { calories: 0, protein: 0, carbs: 0, fat: 0 },
                    water: { target_oz: 128, logged_oz: 0 }
                })
                .select()
                .single();
            day = newDay;
        }
        
        const meals = day.meals || {};
        if (!meals[mealCategory]) meals[mealCategory] = [];
        
        const foodItem = {
            id: crypto.randomUUID(),
            name,
            calories: calories || 0,
            protein: protein || 0,
            carbs: carbs || 0,
            fat: fat || 0,
            logged_at: new Date().toISOString()
        };
        
        meals[mealCategory].push(foodItem);
        
        // Recalculate totals
        const totals = { calories: 0, protein: 0, carbs: 0, fat: 0 };
        Object.values(meals).forEach(items => {
            items.forEach(item => {
                totals.calories += item.calories || 0;
                totals.protein += item.protein || 0;
                totals.carbs += item.carbs || 0;
                totals.fat += item.fat || 0;
            });
        });
        
        const { data: updated } = await supabase
            .from('nutrition_days')
            .update({ meals, totals, updated_at: new Date().toISOString() })
            .eq('id', day.id)
            .select()
            .single();
        
        res.json({ nutrition_day: updated, meal_type: mealCategory });
    } catch (error) {
        console.error('Add food error:', error);
        res.status(500).json({ error: 'Failed to add food' });
    }
});

app.put('/api/v2/nutrition/food', authenticateToken, async (req, res) => {
    try {
        const { food_id, name, calories, protein, carbs, fat, meal_type } = req.body;
        const today = new Date().toISOString().split('T')[0];
        
        const { data: day } = await supabase
            .from('nutrition_days')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('date', today)
            .single();
        
        if (!day) return res.status(404).json({ error: 'No nutrition data for today' });
        
        const meals = day.meals || {};
        let found = false;
        let oldMealType = null;
        
        // Find and update the food item
        for (const [mType, items] of Object.entries(meals)) {
            const index = items.findIndex(i => i.id === food_id);
            if (index >= 0) {
                oldMealType = mType;
                if (meal_type && meal_type !== mType) {
                    // Move to different meal category
                    const [item] = items.splice(index, 1);
                    item.name = name || item.name;
                    item.calories = calories ?? item.calories;
                    item.protein = protein ?? item.protein;
                    item.carbs = carbs ?? item.carbs;
                    item.fat = fat ?? item.fat;
                    if (!meals[meal_type]) meals[meal_type] = [];
                    meals[meal_type].push(item);
                } else {
                    items[index] = { ...items[index], name, calories, protein, carbs, fat };
                }
                found = true;
                break;
            }
        }
        
        if (!found) return res.status(404).json({ error: 'Food item not found' });
        
        // Recalculate totals
        const totals = { calories: 0, protein: 0, carbs: 0, fat: 0 };
        Object.values(meals).forEach(items => {
            items.forEach(item => {
                totals.calories += item.calories || 0;
                totals.protein += item.protein || 0;
                totals.carbs += item.carbs || 0;
                totals.fat += item.fat || 0;
            });
        });
        
        const { data: updated } = await supabase
            .from('nutrition_days')
            .update({ meals, totals })
            .eq('id', day.id)
            .select()
            .single();
        
        res.json({ nutrition_day: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update food' });
    }
});

app.delete('/api/v2/nutrition/food', authenticateToken, async (req, res) => {
    try {
        const { food_id } = req.body;
        const today = new Date().toISOString().split('T')[0];
        
        const { data: day } = await supabase
            .from('nutrition_days')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('date', today)
            .single();
        
        if (!day) return res.status(404).json({ error: 'No nutrition data' });
        
        const meals = day.meals || {};
        
        for (const [mType, items] of Object.entries(meals)) {
            const index = items.findIndex(i => i.id === food_id);
            if (index >= 0) {
                items.splice(index, 1);
                break;
            }
        }
        
        // Recalculate totals
        const totals = { calories: 0, protein: 0, carbs: 0, fat: 0 };
        Object.values(meals).forEach(items => {
            items.forEach(item => {
                totals.calories += item.calories || 0;
                totals.protein += item.protein || 0;
                totals.carbs += item.carbs || 0;
                totals.fat += item.fat || 0;
            });
        });
        
        const { data: updated } = await supabase
            .from('nutrition_days')
            .update({ meals, totals })
            .eq('id', day.id)
            .select()
            .single();
        
        res.json({ nutrition_day: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete food' });
    }
});

app.post('/api/v2/nutrition/water', authenticateToken, async (req, res) => {
    try {
        const { oz } = req.body;
        const today = new Date().toISOString().split('T')[0];
        
        let { data: day } = await supabase
            .from('nutrition_days')
            .select('*')
            .eq('user_id', req.user.userId)
            .eq('date', today)
            .single();
        
        if (!day) {
            const { data: newDay } = await supabase
                .from('nutrition_days')
                .insert({
                    user_id: req.user.userId,
                    date: today,
                    meals: {},
                    totals: { calories: 0, protein: 0, carbs: 0, fat: 0 },
                    water: { target_oz: 128, logged_oz: 0 }
                })
                .select()
                .single();
            day = newDay;
        }
        
        const water = day.water || { target_oz: 128, logged_oz: 0 };
        water.logged_oz = (water.logged_oz || 0) + (oz || 0);
        
        const { data: updated } = await supabase
            .from('nutrition_days')
            .update({ water })
            .eq('id', day.id)
            .select()
            .single();
        
        res.json({ nutrition_day: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to log water' });
    }
});

// ═══════════════════════════════════════════════════════════════
// V2 LEARNING ROUTES
// ═══════════════════════════════════════════════════════════════

app.get('/api/v2/learning/profile', authenticateToken, async (req, res) => {
    try {
        const { data } = await supabase
            .from('learning_profiles')
            .select('*')
            .eq('user_id', req.user.userId)
            .single();
        
        res.json({ profile: data || { exercise_dictionary: {}, workout_patterns: [], food_preferences: {} } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

app.post('/api/v2/learning/parse-exercise', authenticateToken, async (req, res) => {
    try {
        const { input } = req.body;
        
        // Extract weight, reps, sets from input string
        function extractNumbers(str) {
            const result = { weight: 0, reps: 0, sets: 1 };
            // Pattern: "185 x 5", "185lbs x 5", "185 5x3", etc.
            const wxr = str.match(/(\d+)\s*(?:lbs?|pounds?)?\s*[x×]\s*(\d+)/i);
            if (wxr) {
                result.weight = parseInt(wxr[1]);
                result.reps = parseInt(wxr[2]);
            }
            // Pattern: "3x10" (sets x reps) when appears after weight
            const sxr = str.match(/(\d+)\s*[x×]\s*(\d+)\s*[x×]\s*(\d+)/i);
            if (sxr) {
                result.weight = parseInt(sxr[1]);
                result.sets = parseInt(sxr[2]);
                result.reps = parseInt(sxr[3]);
            }
            return result;
        }
        
        const numbers = extractNumbers(input);
        
        // Common abbreviations
        const abbrevs = {
            'fb bb': 'Flat Bench Barbell Press', 'bench': 'Flat Bench Barbell Press',
            'inc bb': 'Incline Barbell Press', 'incline': 'Incline Bench Press',
            'ohp': 'Overhead Press', 'dl': 'Deadlift',
            'squat': 'Barbell Back Squat', 'bb row': 'Barbell Row'
        };
        
        const lower = input.toLowerCase();
        for (const [abbr, name] of Object.entries(abbrevs)) {
            if (lower.includes(abbr)) {
                return res.json({ parsed: { 
                    standard_name: name, category: 'other', confidence: 0.9,
                    weight: numbers.weight, reps: numbers.reps, sets: numbers.sets
                }});
            }
        }
        
        // Use AI for unknown exercises
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 256,
            messages: [{ role: 'user', content: `Parse exercise: "${input}". Return JSON only: {"standard_name":"Exercise Name","category":"chest|back|shoulders|arms|legs|core|other"}` }]
        });
        
        const parsed = JSON.parse(message.content[0].text.replace(/```json\n?|\n?```/g, ''));
        // Merge AI result with extracted numbers
        parsed.weight = parsed.weight || numbers.weight;
        parsed.reps = parsed.reps || numbers.reps;
        parsed.sets = parsed.sets || numbers.sets;
        res.json({ parsed });
    } catch (error) {
        res.status(500).json({ error: 'Failed to parse exercise' });
    }
});

app.post('/api/v2/learning/predict-next', authenticateToken, async (req, res) => {
    try {
        const { current_exercises } = req.body;
        
        // Simple prediction based on common patterns
        const patterns = {
            'Flat Bench Barbell Press': { exercise: 'Incline Dumbbell Press', category: 'chest', reason: 'Common chest progression' },
            'Barbell Back Squat': { exercise: 'Leg Press', category: 'legs', reason: 'Typical leg day flow' },
            'Deadlift': { exercise: 'Barbell Row', category: 'back', reason: 'Back compound movement' }
        };
        
        const lastExercise = current_exercises[current_exercises.length - 1];
        const prediction = patterns[lastExercise] || { exercise: 'Next Exercise', category: 'other', reason: 'Continue your workout' };
        
        res.json({ prediction });
    } catch (error) {
        res.status(500).json({ error: 'Failed to predict' });
    }
});

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log(`🚀 MACRA Backend v2.0 running on port ${PORT}`);
});















