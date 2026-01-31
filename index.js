require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════
// CLIENTS
// ═══════════════════════════════════════════════════════════════
const supabase = createClient(
    process.env.SUPABASE_URL || '',
    process.env.SUPABASE_SERVICE_KEY || '',
    { auth: { autoRefreshToken: false, persistSession: false } }
);

const anthropic = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const USDA_API_KEY = process.env.USDA_API_KEY;
const USDA_BASE_URL = 'https://api.nal.usda.gov/fdc/v1';

// Subscription Tiers
const TIERS = {
    free: { name: 'Free', aiMessagesPerWeek: 5 },
    athlete: { name: 'Athlete', priceId: process.env.STRIPE_PRICE_ATHLETE, aiMessagesPerWeek: 50 },
    pro: { name: 'Pro', priceId: process.env.STRIPE_PRICE_PRO, aiMessagesPerWeek: 200 },
    elite: { name: 'Elite', priceId: process.env.STRIPE_PRICE_ELITE, aiMessagesPerWeek: -1 }
};

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════
app.use(helmet());
app.use(cors({
    origin: ['https://macra.umbrassi.com', 'https://macra.pages.dev', 'http://localhost:5173', 'http://localhost:3001'],
    credentials: true
}));
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 500, message: { error: 'Too many requests' } });
app.use(globalLimiter);

// Auth middleware
async function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization header' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Invalid token' });
        
        const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single();
        req.user = {
            id: user.id,
            email: user.email,
            profile: profile || {},
            tier: profile?.subscription_tier || 'free',
            stripeCustomerId: profile?.stripe_customer_id
        };
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Authentication failed' });
    }
}

// Check AI quota
async function checkAIQuota(req, res, next) {
    const tierConfig = TIERS[req.user.tier] || TIERS.free;
    if (tierConfig.aiMessagesPerWeek === -1) return next();
    
    const weekStart = getWeekStart();
    const { count } = await supabase.from('ai_usage').select('*', { count: 'exact', head: true })
        .eq('user_id', req.user.id).gte('created_at', weekStart.toISOString());
    
    if ((count || 0) >= tierConfig.aiMessagesPerWeek) {
        return res.status(429).json({ error: 'AI message limit reached', limit: tierConfig.aiMessagesPerWeek });
    }
    req.aiQuota = { used: count || 0, limit: tierConfig.aiMessagesPerWeek };
    next();
}

function getWeekStart() {
    const now = new Date();
    const day = now.getDay();
    const diff = now.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(now.setDate(diff));
    monday.setHours(0, 0, 0, 0);
    return monday;
}

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════
function extractJSON(text) {
    try { return JSON.parse(text.trim()); } catch (e) {}
    let cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
    try { return JSON.parse(cleaned); } catch (e) {}
    const match = text.match(/\{[\s\S]*\}/);
    if (match) try { return JSON.parse(match[0]); } catch (e) {}
    throw new Error('Could not parse JSON');
}

async function searchUSDA(query, maxResults = 5) {
    if (!USDA_API_KEY) return [];
    try {
        const res = await fetch(`${USDA_BASE_URL}/foods/search?api_key=${USDA_API_KEY}&query=${encodeURIComponent(query)}&pageSize=${maxResults}&dataType=Foundation,SR%20Legacy`);
        const data = await res.json();
        return data.foods || [];
    } catch (e) { return []; }
}

function extractNutrients(food) {
    const nutrients = food.foodNutrients || [];
    const find = (name) => {
        const n = nutrients.find(n => (n.nutrientName || n.nutrient?.name || '').toLowerCase().includes(name.toLowerCase()));
        return n?.amount || n?.value || 0;
    };
    
    // USDA Nutrient IDs for reference:
    // Vitamins: A(1106), C(1162), D(1114), E(1109), K(1185), B1(1165), B2(1166), B3(1167), B5(1170), B6(1175), B7(1176), B9(1177), B12(1178)
    // Minerals: Calcium(1087), Iron(1089), Magnesium(1090), Phosphorus(1091), Potassium(1092), Sodium(1093), Zinc(1095)
    
    return { 
        calories: Math.round(find('energy')), 
        protein: Math.round(find('protein')), 
        carbs: Math.round(find('carbohydrate')), 
        fat: Math.round(find('total lipid') || find('fat')),
        fiber: Math.round(find('fiber')),
        sugar: Math.round(find('sugar')),
        // Vitamins
        vitaminA: Math.round(find('vitamin a')),
        vitaminC: Math.round(find('vitamin c') || find('ascorbic acid')),
        vitaminD: Math.round(find('vitamin d')),
        vitaminE: Math.round(find('vitamin e')),
        vitaminK: Math.round(find('vitamin k')),
        vitaminB1: parseFloat(find('thiamin').toFixed(2)),
        vitaminB2: parseFloat(find('riboflavin').toFixed(2)),
        vitaminB3: Math.round(find('niacin')),
        vitaminB5: parseFloat(find('pantothenic').toFixed(2)),
        vitaminB6: parseFloat(find('vitamin b-6').toFixed(2)),
        vitaminB12: parseFloat(find('vitamin b-12').toFixed(2)),
        folate: Math.round(find('folate')),
        // Minerals
        calcium: Math.round(find('calcium')),
        iron: parseFloat(find('iron').toFixed(1)),
        magnesium: Math.round(find('magnesium')),
        phosphorus: Math.round(find('phosphorus')),
        potassium: Math.round(find('potassium')),
        sodium: Math.round(find('sodium')),
        zinc: parseFloat(find('zinc').toFixed(1)),
        // Extras for supplements
        caffeine: Math.round(find('caffeine')),
        creatine: Math.round(find('creatine'))
    };
}

async function buildUSDAContext(query) {
    const foods = await searchUSDA(query, 3);
    if (!foods.length) return null;
    return foods.map(f => {
        const n = extractNutrients(f);
        let context = `${f.description}: ${n.calories} cal, ${n.protein}g protein, ${n.carbs}g carbs, ${n.fat}g fat`;
        // Add significant micronutrients
        if (n.vitaminC > 0) context += `, ${n.vitaminC}mg Vitamin C`;
        if (n.vitaminD > 0) context += `, ${n.vitaminD}mcg Vitamin D`;
        if (n.vitaminB12 > 0) context += `, ${n.vitaminB12}mcg B12`;
        if (n.calcium > 0) context += `, ${n.calcium}mg Calcium`;
        if (n.iron > 0) context += `, ${n.iron}mg Iron`;
        if (n.caffeine > 0) context += `, ${n.caffeine}mg Caffeine`;
        context += ' per 100g';
        return context;
    }).join('\n');
}

// ═══════════════════════════════════════════════════════════════
// ROUTES: HEALTH
// ═══════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'macra-backend', version: '1.0.0' });
});

// ═══════════════════════════════════════════════════════════════
// ROUTES: AUTH
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/signup', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    try {
        const { data, error } = await supabase.auth.signUp({ email, password, options: { data: { name: name || 'Athlete' } } });
        if (error) throw error;
        
        if (data.user) {
            const athleteCode = 'MACRA-' + Math.random().toString(36).substring(2, 6).toUpperCase();
            await supabase.from('profiles').insert({
                id: data.user.id, email, name: name || 'Athlete', athlete_code: athleteCode,
                subscription_tier: 'free', created_at: new Date().toISOString()
            });
        }
        res.json({ message: 'Account created! Check email to confirm.', user: data.user ? { id: data.user.id, email: data.user.email } : null });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    try {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        
        const { data: profile } = await supabase.from('profiles').select('*').eq('id', data.user.id).single();
        res.json({
            token: data.session.access_token,
            refreshToken: data.session.refresh_token,
            expiresAt: data.session.expires_at,
            user: { id: data.user.id, email: data.user.email, name: profile?.name || 'Athlete', athleteCode: profile?.athlete_code, tier: profile?.subscription_tier || 'free' }
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid email or password' });
    }
});

app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
    
    try {
        const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
        if (error) throw error;
        res.json({ token: data.session.access_token, refreshToken: data.session.refresh_token, expiresAt: data.session.expires_at });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    try {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: 'https://macra.umbrassi.com/reset-password'
        });
        if (error) throw error;
        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error('Password reset error:', error);
        // Don't reveal if email exists or not for security
        res.json({ message: 'If an account exists, a reset email has been sent' });
    }
});

// ═══════════════════════════════════════════════════════════════
// ROUTES: AI
// ═══════════════════════════════════════════════════════════════
app.post('/api/ai/parse', authenticateUser, checkAIQuota, async (req, res) => {
    const { input } = req.body;
    if (!input || input.length > 1000) return res.status(400).json({ error: 'Valid input required (max 1000 chars)' });
    
    try {
        const foodKeywords = ['ate', 'eat', 'had', 'drink', 'breakfast', 'lunch', 'dinner', 'snack', 'chicken', 'rice', 'eggs', 'protein', 'shake', 'pre-workout', 'preworkout', 'supplement', 'vitamin', 'carnivore', 'prekaged', 'creatine'];
        const looksLikeFood = foodKeywords.some(kw => input.toLowerCase().includes(kw));
        const usdaContext = looksLikeFood ? await buildUSDAContext(input) : null;
        
        let systemPrompt = `You are a fitness/nutrition parser. Analyze input and determine if it's FOOD, WORKOUT, CARDIO, or WEIGHT/BODY METRICS.
Respond ONLY with valid JSON (no markdown). Format:

For FOOD (including supplements, protein shakes, pre-workouts): 
{"type":"food","data":{"items":[{"name":"Food Name","quantity":"1 scoop","calories":0,"protein":0,"carbs":0,"fat":0,"fiber":0,"sugar":0,"micronutrients":{"vitaminC":0,"vitaminD":0,"vitaminB12":0,"calcium":0,"iron":0,"magnesium":0,"potassium":0,"sodium":0,"caffeine":0,"creatine":0}}],"totals":{"calories":0,"protein":0,"carbs":0,"fat":0},"mealType":"supplement"}}

For common supplements, use these known values:
- Pre-Kaged Elite (1 scoop): 25 cal, 0g protein, 5g carbs, caffeine 388mg, creatine 5g (total), vitaminB6 35mg, vitaminB12 1000mcg, citrulline 10g, beta-alanine 3.2g
- Carnivore/Carnivor Protein (1 scoop): 120 cal, 23g protein, 8g carbs, 0g fat, creatine (added BCAAs)

For WORKOUT: {"type":"workout","data":{"exercises":[{"name":"Exercise","sets":3,"reps":10,"weight":135,"category":"chest|back|shoulders|arms|legs|core"}]}}

For CARDIO: {"type":"cardio","data":{"activity":"Running","duration":30,"distance":3.5,"caloriesBurned":300}}

For WEIGHT/BODY METRICS (when user logs their body weight, body fat, or measurements):
{"type":"weight","data":{"weight":185,"unit":"lbs","bodyFat":null,"measurements":null,"note":"morning weigh-in"}}

Weight triggers: "weighed", "weight is", "scale said", "i'm at", "body weight", "lbs", "kg", "pounds", "kilos"
Include micronutrients when available, especially for supplements and fortified foods. Zero values can be omitted.`;
        
        if (usdaContext) systemPrompt += `\n\nUSDA Reference (use for accuracy):\n${usdaContext}`;
        
        const response = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514', max_tokens: 1024, system: systemPrompt,
            messages: [{ role: 'user', content: input }]
        });
        
        const result = extractJSON(response.content[0].text);
        await supabase.from('ai_usage').insert({ user_id: req.user.id, usage_type: 'parse', tokens_used: 500 });
        
        res.json({ success: true, result, usdaEnhanced: !!usdaContext, quota: req.aiQuota });
    } catch (error) {
        console.error('AI parse error:', error);
        res.status(500).json({ error: 'Failed to parse input' });
    }
});

app.get('/api/ai/quota', authenticateUser, async (req, res) => {
    const tierConfig = TIERS[req.user.tier] || TIERS.free;
    const weekStart = getWeekStart();
    const { count } = await supabase.from('ai_usage').select('*', { count: 'exact', head: true })
        .eq('user_id', req.user.id).gte('created_at', weekStart.toISOString());
    
    res.json({
        tier: req.user.tier, used: count || 0,
        limit: tierConfig.aiMessagesPerWeek === -1 ? 'unlimited' : tierConfig.aiMessagesPerWeek,
        remaining: tierConfig.aiMessagesPerWeek === -1 ? 'unlimited' : Math.max(0, tierConfig.aiMessagesPerWeek - (count || 0))
    });
});

// ═══════════════════════════════════════════════════════════════
// ROUTES: NUTRITION
// ═══════════════════════════════════════════════════════════════
app.get('/api/nutrition/search', authenticateUser, async (req, res) => {
    const { q, limit = 10 } = req.query;
    if (!q) return res.status(400).json({ error: 'Search query required' });
    
    const foods = await searchUSDA(q, Math.min(parseInt(limit), 25));
    const results = foods.map(f => ({ fdcId: f.fdcId, name: f.description, nutrients: extractNutrients(f) }));
    res.json({ query: q, count: results.length, results });
});

app.get('/api/nutrition/common', authenticateUser, (req, res) => {
    res.json({ foods: [
        { name: 'Eggs (2 large)', calories: 140, protein: 12, carbs: 1, fat: 10 },
        { name: 'Chicken Breast (4oz)', calories: 165, protein: 31, carbs: 0, fat: 4 },
        { name: 'White Rice (1 cup)', calories: 205, protein: 4, carbs: 45, fat: 0 },
        { name: 'Protein Shake', calories: 120, protein: 25, carbs: 3, fat: 1 },
        { name: 'Banana', calories: 105, protein: 1, carbs: 27, fat: 0 },
        { name: 'Greek Yogurt (1 cup)', calories: 130, protein: 17, carbs: 8, fat: 1 },
        { name: 'Salmon (4oz)', calories: 230, protein: 25, carbs: 0, fat: 14 }
    ]});
});

// ═══════════════════════════════════════════════════════════════
// ROUTES: USER
// ═══════════════════════════════════════════════════════════════
app.get('/api/user/profile', authenticateUser, async (req, res) => {
    const { data } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
    res.json({
        id: data.id, email: data.email, name: data.name, athleteCode: data.athlete_code,
        tier: data.subscription_tier, goals: data.goals || { calories: 2000, protein: 150, carbs: 200, fat: 65 }
    });
});

app.put('/api/user/profile', authenticateUser, async (req, res) => {
    const { name, goals } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (name) updates.name = name;
    if (goals) updates.goals = goals;
    
    const { data } = await supabase.from('profiles').update(updates).eq('id', req.user.id).select().single();
    res.json({ message: 'Profile updated', profile: { name: data.name, goals: data.goals } });
});

app.post('/api/user/activity', authenticateUser, async (req, res) => {
    const { type, data, date } = req.body;
    if (!type || !data) return res.status(400).json({ error: 'Type and data required' });
    
    const { data: activity, error } = await supabase.from('activities').insert({
        user_id: req.user.id, activity_type: type, activity_data: data,
        activity_date: date || new Date().toISOString().split('T')[0], created_at: new Date().toISOString()
    }).select().single();
    
    if (error) return res.status(500).json({ error: 'Failed to save activity' });
    res.json({ message: 'Activity saved', activity });
});

app.get('/api/user/data', authenticateUser, async (req, res) => {
    const { data: activities } = await supabase.from('activities').select('*').eq('user_id', req.user.id)
        .order('created_at', { ascending: false }).limit(500);
    const { data: prs } = await supabase.from('personal_records').select('*').eq('user_id', req.user.id);
    res.json({ activities: activities || [], prs: prs || [] });
});

app.get('/api/user/stats', authenticateUser, async (req, res) => {
    const weekStart = getWeekStart();
    const { data: activities } = await supabase.from('activities').select('*').eq('user_id', req.user.id)
        .gte('activity_date', weekStart.toISOString().split('T')[0]);
    
    let weeklyCalories = 0, weeklyProtein = 0, weeklyWorkouts = 0, weeklyVolume = 0;
    (activities || []).forEach(a => {
        if (a.activity_type === 'food') {
            weeklyCalories += a.activity_data?.totals?.calories || 0;
            weeklyProtein += a.activity_data?.totals?.protein || 0;
        } else if (a.activity_type === 'workout') {
            weeklyWorkouts++;
            (a.activity_data?.exercises || []).forEach(ex => {
                weeklyVolume += (ex.weight || 0) * (ex.sets || 1) * (ex.reps || 1);
            });
        }
    });
    
    const { count: prCount } = await supabase.from('personal_records').select('*', { count: 'exact', head: true }).eq('user_id', req.user.id);
    res.json({ streak: 0, weeklyCalories, weeklyProtein: Math.round(weeklyProtein), weeklyWorkouts, weeklyVolume, totalPRs: prCount || 0 });
});

// ═══════════════════════════════════════════════════════════════
// ROUTES: STRIPE
// ═══════════════════════════════════════════════════════════════
app.get('/api/stripe/tiers', (req, res) => {
    const tiers = Object.entries(TIERS).map(([key, tier]) => ({
        id: key, name: tier.name,
        aiMessagesPerWeek: tier.aiMessagesPerWeek === -1 ? 'Unlimited' : tier.aiMessagesPerWeek,
        price: key === 'free' ? 0 : key === 'athlete' ? 5 : key === 'pro' ? 12 : 20
    }));
    res.json({ tiers });
});

app.post('/api/stripe/checkout', authenticateUser, async (req, res) => {
    const { tier } = req.body;
    if (!tier || !TIERS[tier] || tier === 'free') return res.status(400).json({ error: 'Invalid tier' });
    
    try {
        const session = await stripe.checkout.sessions.create({
            mode: 'subscription', payment_method_types: ['card'], customer_email: req.user.email,
            line_items: [{ price: TIERS[tier].priceId, quantity: 1 }],
            success_url: `https://macra.umbrassi.com/settings?success=true&tier=${tier}`,
            cancel_url: 'https://macra.umbrassi.com/settings?canceled=true',
            metadata: { userId: req.user.id, tier },
            subscription_data: { trial_period_days: 7, metadata: { userId: req.user.id, tier } }
        });
        res.json({ checkoutUrl: session.url });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create checkout' });
    }
});

app.post('/api/stripe/portal', authenticateUser, async (req, res) => {
    if (!req.user.stripeCustomerId) return res.status(400).json({ error: 'No active subscription' });
    
    const session = await stripe.billingPortal.sessions.create({
        customer: req.user.stripeCustomerId, return_url: 'https://macra.umbrassi.com/settings'
    });
    res.json({ portalUrl: session.url });
});

// Donation/tip endpoint
app.post('/api/stripe/donate', authenticateUser, async (req, res) => {
    const { amount } = req.body;
    const validAmounts = [5, 10, 25, 50, 100];
    
    if (!amount || !validAmounts.includes(amount)) {
        return res.status(400).json({ error: 'Invalid donation amount' });
    }
    
    try {
        const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            payment_method_types: ['card'],
            customer_email: req.user.email,
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'MACRA Support',
                        description: `Thank you for supporting MACRA! 💜`,
                    },
                    unit_amount: amount * 100, // cents
                },
                quantity: 1
            }],
            success_url: 'https://macra.umbrassi.com/settings?donated=true',
            cancel_url: 'https://macra.umbrassi.com/settings',
            metadata: { userId: req.user.id, type: 'donation', amount }
        });
        res.json({ checkoutUrl: session.url });
    } catch (error) {
        console.error('Donation checkout error:', error);
        res.status(500).json({ error: 'Failed to create donation checkout' });
    }
});

// ═══════════════════════════════════════════════════════════════
// USER DATA SYNC ENDPOINTS
// ═══════════════════════════════════════════════════════════════

// Save user data to cloud
app.post('/api/user/sync', authenticateUser, async (req, res) => {
    try {
        const { activities, goals, profile, stats, prs, weightHistory } = req.body;
        
        const { error } = await supabase.from('user_data').upsert({
            user_id: req.user.id,
            activities: activities || {},
            goals: goals || {},
            profile_data: profile || {},
            stats: stats || {},
            prs: prs || {},
            weight_history: weightHistory || [],
            updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });
        
        if (error) throw error;
        res.json({ success: true, synced_at: new Date().toISOString() });
    } catch (error) {
        console.error('Sync error:', error);
        res.status(500).json({ error: 'Failed to sync data' });
    }
});

// Load user data from cloud
app.get('/api/user/data', authenticateUser, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_data')
            .select('*')
            .eq('user_id', req.user.id)
            .single();
        
        if (error && error.code !== 'PGRST116') throw error; // PGRST116 = no rows found
        
        if (!data) {
            return res.json({ 
                activities: {}, 
                goals: { calories: 2000, protein: 150, carbs: 200, fat: 65 },
                profile: {},
                stats: { streak: 0, weeklyPoints: 0 },
                prs: {},
                weightHistory: []
            });
        }
        
        res.json({
            activities: data.activities || {},
            goals: data.goals || {},
            profile: data.profile_data || {},
            stats: data.stats || {},
            prs: data.prs || {},
            weightHistory: data.weight_history || []
        });
    } catch (error) {
        console.error('Load error:', error);
        res.status(500).json({ error: 'Failed to load data' });
    }
});

app.post('/api/stripe/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).json({ error: 'Invalid signature' });
    }
    
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        await supabase.from('profiles').update({
            subscription_tier: session.metadata.tier, stripe_customer_id: session.customer,
            stripe_subscription_id: session.subscription, subscription_status: 'active', updated_at: new Date().toISOString()
        }).eq('id', session.metadata.userId);
    } else if (event.type === 'customer.subscription.deleted') {
        const sub = event.data.object;
        await supabase.from('profiles').update({
            subscription_tier: 'free', subscription_status: 'canceled', updated_at: new Date().toISOString()
        }).eq('stripe_customer_id', sub.customer);
    }
    
    res.json({ received: true });
});

// ═══════════════════════════════════════════════════════════════
// GOOGLE PLACES API - NEARBY GYMS
// ═══════════════════════════════════════════════════════════════
const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY;

app.get('/api/places/nearby', authenticateUser, async (req, res) => {
    const { lat, lng, type = 'gym', radius = 16000 } = req.query; // Default 10 mile radius
    
    if (!lat || !lng) {
        return res.status(400).json({ error: 'Latitude and longitude required' });
    }
    
    if (!GOOGLE_PLACES_API_KEY) {
        // Return mock data if no API key configured
        return res.json({
            results: [
                { place_id: 'mock1', name: 'Second Chance Gym', vicinity: 'Brandon, FL', rating: 4.8, user_ratings_total: 156, distance: 2.3 },
                { place_id: 'mock2', name: 'Muscle Asylum', vicinity: 'Tampa, FL', rating: 4.6, user_ratings_total: 89, distance: 8.1 },
                { place_id: 'mock3', name: "Rich's Health Club @ Southpointe", vicinity: 'Brandon, FL', rating: 4.9, user_ratings_total: 234, distance: 3.5 },
                { place_id: 'mock4', name: 'Planet Fitness', vicinity: 'Brandon, FL', rating: 4.2, user_ratings_total: 412, distance: 1.8 },
                { place_id: 'mock5', name: 'LA Fitness', vicinity: 'Tampa, FL', rating: 4.0, user_ratings_total: 567, distance: 5.2 }
            ],
            mock: true
        });
    }
    
    try {
        const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${lat},${lng}&radius=${radius}&type=${type}&keyword=gym|fitness&key=${GOOGLE_PLACES_API_KEY}`;
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.status !== 'OK' && data.status !== 'ZERO_RESULTS') {
            console.error('Google Places API error:', data.status, data.error_message);
            return res.status(500).json({ error: 'Places API error', status: data.status });
        }
        
        // Calculate distance for each result
        const results = (data.results || []).map(place => {
            const placeLat = place.geometry?.location?.lat;
            const placeLng = place.geometry?.location?.lng;
            let distance = null;
            
            if (placeLat && placeLng) {
                distance = calculateDistance(parseFloat(lat), parseFloat(lng), placeLat, placeLng);
            }
            
            return {
                place_id: place.place_id,
                name: place.name,
                vicinity: place.vicinity,
                rating: place.rating,
                user_ratings_total: place.user_ratings_total,
                distance: distance,
                photo_reference: place.photos?.[0]?.photo_reference,
                open_now: place.opening_hours?.open_now
            };
        });
        
        // Sort by distance
        results.sort((a, b) => (a.distance || 999) - (b.distance || 999));
        
        res.json({ results: results.slice(0, 15) });
        
    } catch (error) {
        console.error('Places API error:', error);
        res.status(500).json({ error: 'Failed to fetch nearby places' });
    }
});

// Haversine formula to calculate distance in miles
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 3959; // Earth's radius in miles
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return Math.round(R * c * 10) / 10; // Round to 1 decimal
}

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log(`🏋️ MACRA Backend running on port ${PORT}`);
});
