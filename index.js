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
        const n = nutrients.find(n => (n.nutrientName || n.nutrient?.name || '').toLowerCase().includes(name));
        return n?.amount || n?.value || 0;
    };
    return { calories: Math.round(find('energy')), protein: Math.round(find('protein')), carbs: Math.round(find('carbohydrate')), fat: Math.round(find('total lipid') || find('fat')) };
}

async function buildUSDAContext(query) {
    const foods = await searchUSDA(query, 3);
    if (!foods.length) return null;
    return foods.map(f => {
        const n = extractNutrients(f);
        return `${f.description}: ${n.calories} cal, ${n.protein}g protein, ${n.carbs}g carbs, ${n.fat}g fat per 100g`;
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

// ═══════════════════════════════════════════════════════════════
// ROUTES: AI
// ═══════════════════════════════════════════════════════════════
app.post('/api/ai/parse', authenticateUser, checkAIQuota, async (req, res) => {
    const { input } = req.body;
    if (!input || input.length > 1000) return res.status(400).json({ error: 'Valid input required (max 1000 chars)' });
    
    try {
        const foodKeywords = ['ate', 'eat', 'had', 'drink', 'breakfast', 'lunch', 'dinner', 'snack', 'chicken', 'rice', 'eggs', 'protein'];
        const looksLikeFood = foodKeywords.some(kw => input.toLowerCase().includes(kw));
        const usdaContext = looksLikeFood ? await buildUSDAContext(input) : null;
        
        let systemPrompt = `You are a fitness/nutrition parser. Analyze input and determine if it's FOOD, WORKOUT, or CARDIO.
Respond ONLY with valid JSON (no markdown). Format:
For FOOD: {"type":"food","data":{"items":[{"name":"Food","quantity":"amount","calories":0,"protein":0,"carbs":0,"fat":0}],"totals":{"calories":0,"protein":0,"carbs":0,"fat":0}}}
For WORKOUT: {"type":"workout","data":{"exercises":[{"name":"Exercise","sets":3,"reps":10,"weight":135,"category":"chest|back|shoulders|arms|legs|core"}]}}
For CARDIO: {"type":"cardio","data":{"activity":"Running","duration":30,"distance":3.5,"caloriesBurned":300}}`;
        
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
// START SERVER
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log(`🏋️ MACRA Backend running on port ${PORT}`);
});
