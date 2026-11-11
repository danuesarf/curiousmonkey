-- SAML identity providers in each account, with the issuer from their metadata. IAM Identity Center creates one
-- (AWSSSO_<id>_DO_NOT_DELETE) in every account it is given, so the issuer is what tells which Identity Center
-- instance can sign people in, and whether an account trusts more than one.
CREATE TABLE IF NOT EXISTS saml_providers (
  account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  arn         text NOT NULL,
  name        text NOT NULL,
  issuer      text,                       -- entityID of the IdP metadata; null when it could not be read
  created_at  timestamptz,
  seen_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, arn)
);
