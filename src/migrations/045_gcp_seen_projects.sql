-- Projects a Google Cloud connection's reader can see, in or out of its scope, with the organization they sit under.
-- A service account from one of them that is under one of your organizations is yours, not an outsider, even when no
-- connection reads that project. Replaced on each scan of the connection.
CREATE TABLE IF NOT EXISTS gcp_seen_projects (
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  project_id     text NOT NULL,
  number         text,
  organization   text,                 -- organizations/<id>, or null when it sits under none the reader can see
  PRIMARY KEY (connection_id, project_id)
);
CREATE INDEX IF NOT EXISTS gcp_seen_projects_number ON gcp_seen_projects (number);
