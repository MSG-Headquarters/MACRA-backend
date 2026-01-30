# MACRA Backend API

Backend service for MACRA fitness tracker. Handles authentication, AI parsing, nutrition data, and subscriptions.

## Architecture

```
Frontend (macra.umbrassi.com)
        ↓
Backend (Railway)
   ├── /api/auth     → Supabase Auth
   ├── /api/ai       → Claude API (parsing, insights)
   ├── /api/nutrition → USDA FoodData Central
   ├── /api/stripe   → Stripe Subscriptions
   └── /api/user     → User data & stats
        ↓
Database (Supabase)
```

## Subscription Tiers

| Tier | Price | AI Messages/Week | Features |
|------|-------|------------------|----------|
| Free | $0 | 5 | Basic tracking, manual entry |
| Athlete | $5/mo | 50 | AI logging, USDA nutrition, PR tracking |
| Pro | $12/mo | 200 | Intelligence Hub, advanced analytics |
| Elite | $20/mo | Unlimited | Everything + priority support |

## Setup

### 1. Create Supabase Project
1. Go to [supabase.com](https://supabase.com)
2. Create new project
3. Run `supabase-schema.sql` in SQL Editor
4. Copy URL and Service Role Key

### 2. Create Stripe Products
1. Go to [Stripe Dashboard](https://dashboard.stripe.com)
2. Create 3 products: Athlete ($5), Pro ($12), Elite ($20)
3. Copy Price IDs

### 3. Deploy to Railway
1. Push to GitHub
2. Connect repo to Railway
3. Add environment variables:

```
PORT=3000
NODE_ENV=production
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_KEY=xxx
CLAUDE_API_KEY=sk-ant-xxx
USDA_API_KEY=cw8lcPMtxxXp1iNX6YPUfpPuahGVz73wGss8LRTH
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
STRIPE_PRICE_ATHLETE=price_xxx
STRIPE_PRICE_PRO=price_xxx
STRIPE_PRICE_ELITE=price_xxx
```

### 4. Configure Stripe Webhook
1. In Stripe Dashboard → Webhooks
2. Add endpoint: `https://your-railway-url/api/stripe/webhook`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`

## API Endpoints

### Auth
- `POST /api/auth/signup` - Register
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `POST /api/auth/refresh` - Refresh token

### AI (requires auth)
- `POST /api/ai/parse` - Parse food/workout/cardio input
- `POST /api/ai/insights` - Generate insights
- `GET /api/ai/quota` - Check usage quota

### Nutrition (requires auth)
- `GET /api/nutrition/search?q=chicken` - Search USDA
- `GET /api/nutrition/food/:fdcId` - Get food details
- `GET /api/nutrition/common` - Common foods reference

### Stripe
- `GET /api/stripe/tiers` - Get subscription tiers
- `POST /api/stripe/checkout` - Create checkout session
- `POST /api/stripe/portal` - Manage subscription
- `POST /api/stripe/webhook` - Stripe webhooks

### User (requires auth)
- `GET /api/user/profile` - Get profile
- `PUT /api/user/profile` - Update profile
- `GET /api/user/data` - Get all activities
- `POST /api/user/activity` - Save activity
- `DELETE /api/user/activity/:id` - Delete activity
- `GET /api/user/stats` - Get statistics

## Local Development

```bash
npm install
cp .env.example .env
# Fill in .env values
npm run dev
```

## Tech Stack
- Node.js + Express
- Supabase (Auth + Database)
- Claude API (AI parsing)
- USDA FoodData Central (Nutrition)
- Stripe (Subscriptions)
- Railway (Hosting)
