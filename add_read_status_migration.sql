-- Add read_status column to ticket_comments table for WhatsApp-like read receipts
ALTER TABLE ticket_comments ADD COLUMN IF NOT EXISTS read_status ENUM('sent', 'delivered', 'read') DEFAULT 'sent';

-- Add read_at timestamp to track when messages were read
ALTER TABLE ticket_comments ADD COLUMN IF NOT EXISTS read_at TIMESTAMP NULL;

-- Create index for better performance on read status queries
CREATE INDEX IF NOT EXISTS idx_ticket_comments_read_status ON ticket_comments(read_status);
CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket_id_created_at ON ticket_comments(ticket_id, created_at);
