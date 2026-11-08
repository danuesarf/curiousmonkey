-- Planned accounts: registered by name, ID, environment and OU before anyone deploys the scanner role in them.
-- They hold no access settings and are never scanned until they are onboarded (status becomes 'pending').
ALTER TABLE cloud_accounts DROP CONSTRAINT IF EXISTS cloud_accounts_status_check;
ALTER TABLE cloud_accounts ADD CONSTRAINT cloud_accounts_status_check CHECK (status IN ('planned','pending','connected','error'));
ALTER TABLE cloud_accounts ADD COLUMN note text;            -- who owns it, the ticket, when it is due: free text
ALTER TABLE cloud_accounts ADD COLUMN onboarded_at timestamptz;
