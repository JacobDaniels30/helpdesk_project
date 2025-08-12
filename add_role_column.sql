-- Add role column to users table to support agent registration
ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user' AFTER is_admin;

-- Update existing users with appropriate roles
UPDATE users SET role = 'admin' WHERE is_admin = 1;
UPDATE users SET role = 'user' WHERE is_admin = 0;

-- Create index for role-based queries
CREATE INDEX idx_role ON users(role);
