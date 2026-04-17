-- Audit logging database schema
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    operation VARCHAR(100) NOT NULL,
    key_label VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    details TEXT,
    previous_hash VARCHAR(64),
    hash VARCHAR(64) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_operation ON audit_logs(operation);
CREATE INDEX idx_audit_user ON audit_logs(user_id);

-- Create table for key metadata
CREATE TABLE IF NOT EXISTS key_metadata (
    id SERIAL PRIMARY KEY,
    key_label VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_current BOOLEAN DEFAULT FALSE,
    key_type VARCHAR(50),
    key_size INTEGER,
    created_by VARCHAR(255)
);

CREATE INDEX idx_key_current ON key_metadata(is_current);

-- Create view for compliance reporting
CREATE VIEW compliance_summary AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_operations,
    COUNT(DISTINCT key_label) as keys_used,
    COUNT(DISTINCT user_id) as active_users
FROM audit_logs
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- Function to verify audit chain
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE(
    entry_id INTEGER,
    is_valid BOOLEAN,
    message TEXT
) AS $$
DECLARE
    rec RECORD;
    prev_hash_val TEXT := '0' * 64;
BEGIN
    FOR rec IN SELECT * FROM audit_logs ORDER BY id LOOP
        -- Verify hash
        IF rec.hash != ENCODE(SHA256(CAST(ROW(rec.timestamp, rec.operation, rec.key_label, rec.user_id, rec.details, rec.previous_hash) AS TEXT)), 'hex') THEN
            RETURN QUERY SELECT rec.id, FALSE, 'Hash mismatch';
        END IF;
        
        -- Verify chain
        IF rec.previous_hash != prev_hash_val THEN
            RETURN QUERY SELECT rec.id, FALSE, 'Chain broken';
        END IF;
        
        prev_hash_val := rec.hash;
    END LOOP;
    
    RETURN QUERY SELECT 0, TRUE, 'Audit chain verified';
END;
$$ LANGUAGE plpgsql;