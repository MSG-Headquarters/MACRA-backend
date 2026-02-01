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

const app = express();

const PORT = process.env.PORT || 3000;

// Initialize Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

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
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════

app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'macra-backend', version: '2.0.1', timestamp: new Date().toISOString() });
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
        
        const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
        if (existing) return res.status(400).json({ error: 'Email already registered' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const athleteCode = 'MACRA-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        
        const { data: user, error } = await supabase.from('users').insert({
            email: email.toLowerCase(),
            password_hash: hashedPassword,
            name: name || 'Athlete',
            athlete_code: athleteCode,
            tier: 'free',
            created_at: new Date().toISOString()
        }).select().single();
        
        if (error) throw error;
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
        const { data: profile } = await supabase.from('users').select('*').eq('id', data.user.id).single();
        
        res.json({
            token: data.session.access_token,
            refreshToken: data.session.refresh_token,
            user: {
                id: data.user.id,
                email: data.user.email,
                name: profile?.name || 'Athlete',
                athleteCode: profile?.athlete_code || 'MACRA-0000',
                tier: profile?.tier || 'free'
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
        // In production, send actual email
        res.json({ success: true, message: 'If account exists, reset email sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// ═══════════════════════════════════════════════════════════════
// AI PARSING ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/api/ai/parse', authenticateToken, async (req, res) => {
    try {
        const { input } = req.body;
        if (!input) return res.status(400).json({ error: 'Input required' });
        
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1024,
            messages: [{ role: 'user', content: `Parse this fitness/nutrition input and return JSON only (no markdown):
Input: "${input}"

Return one of these formats:
For food: {"type":"food","data":{"items":[{"name":"food name","calories":0,"protein":0,"carbs":0,"fat":0}],"totals":{"calories":0,"protein":0,"carbs":0,"fat":0},"mealType":"breakfast|lunch|dinner|snack"}}
For workout: {"type":"workout","data":{"exercises":[{"name":"exercise name","weight":0,"sets":0,"reps":0,"category":"chest|back|shoulders|arms|legs|core"}]}}
For cardio: {"type":"cardio","data":{"activity":"activity name","duration":0,"distance":0,"calories":0}}
For weight: {"type":"weight","data":{"weight":0,"unit":"lbs"}}

Be accurate with nutrition estimates. Return ONLY valid JSON.` }]
        });
        
        const text = message.content[0].text;
        const result = JSON.parse(text.replace(/```json\n?|\n?```/g, '').trim());
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
        res.json({ session: data || null });
    } catch (error) {
        console.error('Get active workout error:', error);
        res.status(500).json({ error: 'Failed to get active workout' });
    }
});

app.post('/api/v2/workout/start', authenticateToken, async (req, res) => {
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
        res.json({ session: data });
    } catch (error) {
        console.error('Start workout error:', error);
        res.status(500).json({ error: 'Failed to start workout' });
    }
});

app.post('/api/v2/workout/exercise', authenticateToken, async (req, res) => {
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
        res.json({ session: updated });
    } catch (error) {
        console.error('Add exercise error:', error);
        res.status(500).json({ error: 'Failed to add exercise' });
    }
});

app.delete('/api/v2/workout/exercise', authenticateToken, async (req, res) => {
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
        
        res.json({ session: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete' });
    }
});

app.post('/api/v2/workout/finalize', authenticateToken, async (req, res) => {
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
        
        res.json({ session: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to finalize' });
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
        
        // Common abbreviations
        const abbrevs = {
            'fb bb': 'Flat Bench Barbell Press', 'bench': 'Flat Bench Barbell Press',
            'inc bb': 'Incline Barbell Press', 'ohp': 'Overhead Press',
            'dl': 'Deadlift', 'squat': 'Barbell Back Squat', 'bb row': 'Barbell Row'
        };
        
        const lower = input.toLowerCase();
        for (const [abbr, name] of Object.entries(abbrevs)) {
            if (lower.includes(abbr)) {
                return res.json({ parsed: { standard_name: name, category: 'other', confidence: 0.9 } });
            }
        }
        
        // Use AI for unknown exercises
        const message = await anthropic.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 256,
            messages: [{ role: 'user', content: `Parse exercise: "${input}". Return JSON only: {"standard_name":"Exercise Name","category":"chest|back|shoulders|arms|legs|core|other"}` }]
        });
        
        const parsed = JSON.parse(message.content[0].text.replace(/```json\n?|\n?```/g, ''));
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











