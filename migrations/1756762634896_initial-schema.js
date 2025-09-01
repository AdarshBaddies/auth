exports.up = (pgm) => {
  pgm.sql(`
    -- Enable UUID extension
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    -- Users table with enterprise features
    CREATE TABLE users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token VARCHAR(255),
        email_verification_expires TIMESTAMP,
        mfa_enabled BOOLEAN DEFAULT FALSE,
        mfa_secret VARCHAR(255),
        mfa_backup_codes TEXT[],
        last_login TIMESTAMP,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        password_reset_token VARCHAR(255),
        password_reset_expires TIMESTAMP,
        profile_picture_url VARCHAR(500),
        phone_number VARCHAR(20),
        date_of_birth DATE,
        preferences JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        deleted_at TIMESTAMP
    );

    -- OAuth accounts table
    CREATE TABLE oauth_accounts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        provider_user_id VARCHAR(255) NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(provider, provider_user_id)
    );

    -- Refresh tokens table with enhanced security
    CREATE TABLE refresh_tokens (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL,
        device_info JSONB,
        ip_address INET,
        user_agent TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        revoked_at TIMESTAMP,
        revoked_reason VARCHAR(100)
    );

    -- Audit logs table for compliance
    CREATE TABLE audit_logs (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(100),
        resource_id UUID,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        user_agent TEXT,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
    );

    -- User sessions table
    CREATE TABLE user_sessions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        session_token VARCHAR(255) UNIQUE NOT NULL,
        device_info JSONB,
        ip_address INET,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        last_activity TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );

    -- API keys table for service-to-service authentication
    CREATE TABLE api_keys (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(100) NOT NULL,
        key_hash VARCHAR(255) UNIQUE NOT NULL,
        user_id UUID REFERENCES users(id),
        permissions TEXT[],
        is_active BOOLEAN DEFAULT TRUE,
        expires_at TIMESTAMP,
        last_used TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
    );

    -- User roles and permissions table
    CREATE TABLE roles (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(50) UNIQUE NOT NULL,
        description TEXT,
        permissions TEXT[],
        created_at TIMESTAMP DEFAULT NOW()
    );

    -- User role assignments
    CREATE TABLE user_roles (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
        assigned_by UUID REFERENCES users(id),
        assigned_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP,
        UNIQUE(user_id, role_id)
    );

    -- Create indexes for performance
    CREATE INDEX idx_users_email ON users(email);
    CREATE INDEX idx_users_role ON users(role);
    CREATE INDEX idx_users_status ON users(status);
    CREATE INDEX idx_users_email_verified ON users(email_verified);
    CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
    CREATE INDEX idx_oauth_accounts_provider ON oauth_accounts(provider);
    CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
    CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
    CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
    CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
    CREATE INDEX idx_audit_logs_action ON audit_logs(action);
    CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
    CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
    CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
    CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);

    -- Insert default roles
    INSERT INTO roles (name, description, permissions) VALUES
    ('user', 'Regular user with basic permissions', ARRAY['read:own_profile', 'update:own_profile']),
    ('premium_user', 'Premium user with enhanced features', ARRAY['read:own_profile', 'update:own_profile', 'read:movies', 'create:bookings']),
    ('theater_owner', 'Theater owner with management permissions', ARRAY['read:own_profile', 'update:own_profile', 'manage:theaters', 'manage:movies', 'view:analytics']),
    ('admin', 'System administrator with full access', ARRAY['*']);

    -- Insert admin user (password: admin123)
    INSERT INTO users (email, password_hash, first_name, last_name, role, email_verified, status) 
    VALUES (
        'admin@bookmyshow.com', 
        '$2b$10$rQZ8K9vX8K9vX8K9vX8K9O', 
        'Admin', 
        'User', 
        'admin', 
        true,
        'active'
    );

    -- Assign admin role
    -- NOTE: The 'select from' query is more complex for migrations
    -- This INSERT will be run after the roles and users tables exist.
    INSERT INTO user_roles (user_id, role_id) 
    SELECT u.id, r.id FROM users u, roles r 
    WHERE u.email = 'admin@bookmyshow.com' AND r.name = 'admin';

    -- Create function to update updated_at timestamp
    CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    $$ language 'plpgsql';

    -- Create triggers for updated_at
    CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_oauth_accounts_updated_at BEFORE UPDATE ON oauth_accounts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_refresh_tokens_updated_at BEFORE UPDATE ON refresh_tokens FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    -- Drop triggers first
    DROP TRIGGER update_users_updated_at ON users;
    DROP TRIGGER update_oauth_accounts_updated_at ON oauth_accounts;
    DROP TRIGGER update_refresh_tokens_updated_at ON refresh_tokens;
    DROP TRIGGER update_api_keys_updated_at ON api_keys;

    -- Drop function
    DROP FUNCTION update_updated_at_column;

    -- Drop tables in reverse order to avoid foreign key errors
    DROP TABLE api_keys;
    DROP TABLE user_roles;
    DROP TABLE roles;
    DROP TABLE user_sessions;
    DROP TABLE audit_logs;
    DROP TABLE refresh_tokens;
    DROP TABLE oauth_accounts;
    DROP TABLE users;
  `);
};
