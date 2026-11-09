-- Regions an operator removed from an S3-trail account. The trail reader adds every region that has log files;
-- it must not add these back.
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS excluded_regions text[] NOT NULL DEFAULT '{}';
