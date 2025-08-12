-- Create ticket_comments table for agent responses and notes
CREATE TABLE IF NOT EXISTS ticket_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    agent_id INT NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add internal_notes column to tickets table for agent internal notes
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS internal_notes TEXT;

-- Add assigned_agent_id column to tickets table
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS assigned_agent_id INT;

-- Add role column to users table for agent designation
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';

-- Add archived column to tickets table
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE;

-- Add updated_at column to tickets table
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- Update status enum to include more options
ALTER TABLE tickets MODIFY COLUMN status ENUM('Open', 'In Progress', 'Waiting on User', 'Resolved', 'Closed') DEFAULT 'Open';
