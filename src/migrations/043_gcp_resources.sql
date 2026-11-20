-- Google Cloud resources on the Resources page: buckets, BigQuery datasets and tables, Pub/Sub topics and
-- subscriptions, Cloud KMS keys, Secret Manager secrets, Cloud Run services, Cloud Functions and Artifact Registry
-- repositories, with their resource-level IAM policies (read with each Google Cloud scan, src/gcp/resources.js).
-- A resource belongs to an AWS account or to a Google Cloud connection (and a project in it).
ALTER TABLE resources ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS cloud text NOT NULL DEFAULT 'aws' CHECK (cloud IN ('aws', 'gcp'));
ALTER TABLE resources ADD COLUMN IF NOT EXISTS gcp_connection_id uuid REFERENCES gcp_connections(id) ON DELETE CASCADE;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS project_id text;
ALTER TABLE resources ADD CONSTRAINT resources_owner
  CHECK ((cloud = 'aws' AND account_id IS NOT NULL) OR (cloud = 'gcp' AND gcp_connection_id IS NOT NULL AND account_id IS NULL));
CREATE UNIQUE INDEX IF NOT EXISTS resources_gcp_key ON resources (gcp_connection_id, arn) WHERE gcp_connection_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS resources_cloud ON resources (cloud) WHERE deleted_at IS NULL;
