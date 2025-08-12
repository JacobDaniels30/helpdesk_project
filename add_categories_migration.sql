-- Migration script to add categories to helpdesk system
-- Run this script to add category support to tickets

-- Create categories table
CREATE TABLE IF NOT EXISTS categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    color VARCHAR(7) DEFAULT '#007bff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert predefined categories
INSERT INTO categories (name, description, color) VALUES
('Hardware', 'Physical devices, computers, peripherals', '#dc3545'),
('Software', 'Applications, programs, operating systems', '#28a745'),
('Network', 'Internet, WiFi, connectivity issues', '#ffc107'),
('Account/Access', 'Login issues, permissions, user accounts', '#17a2b8'),
('Email', 'Email-related problems', '#6f42c1'),
('Phone/VoIP', 'Phone system and VoIP issues', '#fd7e14'),
('Printer/Scanner', 'Printing and scanning problems', '#20c997'),
('Other', 'Miscellaneous issues', '#6c757d');

-- Add category column to tickets table
ALTER TABLE tickets ADD COLUMN category_id INT DEFAULT NULL;

-- Add foreign key constraint
ALTER TABLE tickets ADD CONSTRAINT fk_tickets_category 
    FOREIGN KEY (category_id) REFERENCES categories(id);

-- Create index for better performance
CREATE INDEX idx_tickets_category ON tickets(category_id);

-- Update existing tickets with default category (Other)
UPDATE tickets SET category_id = 8 WHERE category_id IS NULL;
