-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       username VARCHAR(50) UNIQUE NOT NULL,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       phone VARCHAR(20) UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       first_name VARCHAR(50),
                       last_name VARCHAR(50),
                       role_id UUID,
                       group_id UUID,
                       status SMALLINT DEFAULT 1 CHECK (status IN (1, 2, 3, 4, 5)), -- 1:Active, 2:Blocked, 3:Banned, 4:Limited, 5:Inactive
                       verification_status SMALLINT DEFAULT 0 CHECK (verification_status IN (0, 1, 2)), -- 0:Pending, 1:Verified, 2:Rejected
                       email_verified BOOLEAN DEFAULT FALSE,
                       phone_verified BOOLEAN DEFAULT FALSE,
                       two_factor_enabled BOOLEAN DEFAULT FALSE,
                       two_factor_secret VARCHAR(255),
                       last_login_at TIMESTAMP,
                       last_login_ip VARCHAR(45),
                       login_attempts INTEGER DEFAULT 0,
                       locked_until TIMESTAMP,
                       avatar VARCHAR(255),
                       metadata JSONB,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       deleted_at TIMESTAMP
);

-- Tokens table
CREATE TABLE tokens (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        token_hash VARCHAR(64) UNIQUE NOT NULL,
                        type VARCHAR(20) NOT NULL CHECK (type IN ('access', 'refresh', 'password_reset', 'email_verify', 'phone_verify')),
                        expires_at TIMESTAMP NOT NULL,
                        is_revoked BOOLEAN DEFAULT FALSE,
                        device_id VARCHAR(255),
                        user_agent TEXT,
                        ip_address VARCHAR(45),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Blacklists table
CREATE TABLE blacklists (
                            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                            type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'phone', 'username', 'ip', 'device', 'domain')),
                            value VARCHAR(255) NOT NULL,
                            reason TEXT,
                            is_active BOOLEAN DEFAULT TRUE,
                            expires_at TIMESTAMP,
                            created_by UUID,
                            metadata JSONB,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Password histories table
CREATE TABLE password_histories (
                                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                    password_hash VARCHAR(255) NOT NULL,
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for users table
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_verification_status ON users(verification_status);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_users_last_login_at ON users(last_login_at);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX idx_users_group_id ON users(group_id);

-- Indexes for tokens table
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_type ON tokens(type);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX idx_tokens_is_revoked ON tokens(is_revoked);
CREATE INDEX idx_tokens_token_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_device_id ON tokens(device_id);
CREATE INDEX idx_tokens_user_type ON tokens(user_id, type);
CREATE INDEX idx_tokens_cleanup ON tokens(expires_at, is_revoked);

-- Indexes for blacklists table
CREATE INDEX idx_blacklists_type ON blacklists(type);
CREATE INDEX idx_blacklists_value ON blacklists(value);
CREATE INDEX idx_blacklists_is_active ON blacklists(is_active);
CREATE INDEX idx_blacklists_expires_at ON blacklists(expires_at);
CREATE INDEX idx_blacklists_type_value ON blacklists(type, value);
CREATE INDEX idx_blacklists_active_check ON blacklists(type, value, is_active, expires_at);

-- Indexes for password_histories table
CREATE INDEX idx_password_histories_user_id ON password_histories(user_id);
CREATE INDEX idx_password_histories_created_at ON password_histories(created_at);
CREATE INDEX idx_password_histories_user_created ON password_histories(user_id, created_at);

-- Composite indexes for complex queries
CREATE INDEX idx_tokens_user_valid ON tokens(user_id, type, is_revoked, expires_at);
CREATE INDEX idx_users_identifier_lookup ON users(username, email, phone);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updating updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tokens_updated_at BEFORE UPDATE ON tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_blacklists_updated_at BEFORE UPDATE ON blacklists
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Cleanup function for expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
DELETE FROM tokens WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ language 'plpgsql';

-- Cleanup function for expired blacklists
CREATE OR REPLACE FUNCTION cleanup_expired_blacklists()
RETURNS void AS $$
BEGIN
DELETE FROM blacklists
WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP;
END;
$$ language 'plpgsql';