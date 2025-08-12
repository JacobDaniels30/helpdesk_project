-- Add SLA columns to tickets table
ALTER TABLE tickets 
ADD COLUMN sla_response_due DATETIME NULL,
ADD COLUMN sla_resolution_due DATETIME NULL;

-- Create SLA policies table
CREATE TABLE IF NOT EXISTS sla_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    urgency VARCHAR(20) NOT NULL UNIQUE,
    response_hours INT NOT NULL,
    resolution_hours INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default SLA policies
INSERT INTO sla_policies (urgency, response_hours, resolution_hours) VALUES
('Low', 24, 72),
('Normal', 8, 24),
('High', 4, 12),
('Critical', 1, 4);
