require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const aiRoutes = require('./routes/ai');
const nutritionRoutes = require('./routes/nutrition');
const stripeRoutes = require('./routes/stripe');
const userRoutes = require('./routes/user');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

// CORS - allow frontend domains
app.use(cors({
    origin: [
        'https://macra.umbrassi.com',
        'https://macra.pages.dev',
        'http://localhost:5173',
        'http://localhost:3001'
    ],
    credentials: true
}));

// Body parsing - raw for Stripe webhooks, JSON for everything else
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // 500 requests per 15 min
    message: { error: 'Too many requests, please try again later' }
});
app.use(globalLimiter);

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        service: 'macra-backend',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/nutrition', nutritionRoutes);
app.use('/api/stripe', stripeRoutes);
app.use('/api/user', userRoutes);

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`🏋️ MACRA Backend running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
