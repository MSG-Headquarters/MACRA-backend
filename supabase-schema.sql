-- MACRA Database Schema for Supabase
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Profiles table (extends auth.users)
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    name TEXT DEFAULT 'Athlete',
    athlete_code TEXT UNIQUE,
    goals JSONB DEFAULT '{"calories": 2000, "protein": 150, "carbs": 200, "fat": 65}',
    
    -- Subscription
    subscription_tier TEXT DEFAULT 'free' CHECK (subscription_tier IN ('free', 'athlete', 'pro', 'elite')),
    subscription_status TEXT DEFAULT 'none',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Activities table (food, workout, cardio)
CREATE TABLE IF NOT EXISTS activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    activity_type TEXT NOT NULL CHECK (activity_type IN ('food', 'workout', 'cardio')),
    activity_data JSONB NOT NULL,
    activity_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Personal Records
CREATE TABLE IF NOT EXISTS personal_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    exercise_key TEXT NOT NULL,
    exercise_name TEXT NOT NULL,
    weight NUMERIC NOT NULL,
    sets INTEGER DEFAULT 1,
    reps INTEGER DEFAULT 1,
    volume NUMERIC,
    pr_type TEXT DEFAULT 'weight',
    achieved_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(user_id, exercise_key)
);

-- AI Usage tracking
CREATE TABLE IF NOT EXISTS ai_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    usage_type TEXT NOT NULL,
    tokens_used INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Friends / Social
CREATE TABLE IF NOT EXISTS friendships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    friend_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'blocked')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(user_id, friend_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_activities_user_date ON activities(user_id, activity_date DESC);
CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_ai_usage_user_date ON ai_usage(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_athlete_code ON profiles(athlete_code);
CREATE INDEX IF NOT EXISTS idx_profiles_stripe_customer ON profiles(stripe_customer_id);

-- Row Level Security
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE personal_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE friendships ENABLE ROW LEVEL SECURITY;

-- Policies: Users can only access their own data
CREATE POLICY "Users can view own profile" ON profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can view own activities" ON activities
    FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Users can view own PRs" ON personal_records
    FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Users can view own AI usage" ON ai_usage
    FOR SELECT USING (auth.uid() = user_id);

-- Service role can do everything (for backend)
CREATE POLICY "Service role full access profiles" ON profiles
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access activities" ON activities
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access prs" ON personal_records
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access ai_usage" ON ai_usage
    FOR ALL USING (auth.role() = 'service_role');

-- Function to auto-create profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, name, athlete_code)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', 'Athlete'),
        'MACRA-' || UPPER(SUBSTRING(MD5(NEW.id::TEXT) FROM 1 FOR 4))
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create profile on signup
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Grant permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
