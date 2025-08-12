-- Create login_attempts table for comprehensive login tracking
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    failure_reason VARCHAR(100),
    user_id INT,
    country VARCHAR(100),
    city VARCHAR(100),
    device_info VARCHAR(255),
    attempt_count INT DEFAULT 1,
    INDEX idx_email_time (email, attempt_time),
    INDEX idx_ip_time (ip_address, attempt_time),
    INDEX idx_user_time (user_id, attempt_time),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add security tracking columns to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS failed_login_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_failed_login DATETIME,
ADD COLUMN IF NOT EXISTS account_locked_until DATETIME,
ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45),
ADD COLUMN IF NOT EXISTS last_login_time DATETIME,
ADD COLUMN IF NOT EXISTS total_logins INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS suspicious_activity_count INT DEFAULT 0;

-- Create admin activity log table
CREATE TABLE IF NOT EXISTS admin_security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT,
    action_type VARCHAR(50) NOT NULL,
    target_user_id INT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_admin_time (admin_user_id, created_at),
    INDEX idx_action_type (action_type, created_at)
);
