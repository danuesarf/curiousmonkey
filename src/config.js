// All configuration comes from environment variables. See .env.example.
const env = process.env;
const bool = (v, d = false) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(v));
const list = (v, d) => (v ? v : d).split(',').map((s) => s.trim()).filter(Boolean);

export const config = {
  env: env.NODE_ENV || 'development',
  port: Number(env.PORT || 8080),
  databaseUrl: env.DATABASE_URL || 'postgres://cm:cm@localhost:5432/cm',
  databaseSsl: bool(env.DATABASE_SSL, false),
  publicUrl: (env.PUBLIC_URL || 'http://localhost:8080').replace(/\/$/, ''),
  sessionSecret: env.SESSION_SECRET || '',
  dataEncryptionKey: env.DATA_ENCRYPTION_KEY || '',
  cookieSecure: bool(env.COOKIE_SECURE, env.NODE_ENV === 'production'),
  sessionHours: Number(env.SESSION_HOURS || 12),
  trustProxy: bool(env.TRUST_PROXY, false),

  // 'aws' talks to real AWS. 'demo' generates a believable fake estate so the portal can be tried without credentials.
  awsMode: env.AWS_MODE || 'aws',

  scanner: {
    principalArn: env.SCANNER_PRINCIPAL_ARN || '',
    roleName: env.SCANNER_ROLE_NAME || 'CuriousMonkeyScanner',
    defaultRegions: list(env.DEFAULT_REGIONS, 'us-east-1,ap-southeast-1,ap-southeast-3'),
    // CloudTrail event history holds 90 days; that is the most we can look back.
    lookbackDays: Math.min(Number(env.LOOKBACK_DAYS || 90), 90),
    overlapMinutes: Number(env.SCAN_OVERLAP_MINUTES || 30),
    deliveryLagMinutes: Number(env.SCAN_DELIVERY_LAG_MINUTES || 15),
    sliceHours: Number(env.SCAN_SLICE_HOURS || 6),
    lookupDelayMs: Number(env.LOOKUP_DELAY_MS ?? 520), // LookupEvents allows 2 calls a second
    advisorConcurrency: Number(env.ADVISOR_CONCURRENCY || 3),
    provisionalEveryMs: Number(env.PROVISIONAL_EVERY_SECONDS ?? 300) * 1000,   // refresh results while a long read runs
    sessionRetentionDays: Math.max(1, Number(env.SESSION_RETENTION_DAYS || 30)),   // session replay; counts are kept regardless
  },

  schedule: {
    at: env.SCAN_AT || '01:00',
    tz: env.SCAN_TZ || 'Asia/Jakarta',
    pollSeconds: Number(env.WORKER_POLL_SECONDS || 10),
  },

  ai: {
    enabled: bool(env.BEDROCK_ENABLED, false),
    region: env.BEDROCK_REGION || env.AWS_REGION || 'us-east-1',
    modelId: env.BEDROCK_MODEL_ID || 'anthropic.claude-sonnet-4-5-20250929-v1:0',
    maxRetries: Number(env.AI_MAX_RETRIES || 2),
    maxTokens: Number(env.AI_MAX_TOKENS || 8000),
  },

  // Also run each draft through AWS IAM Access Analyzer ValidatePolicy (needs access-analyzer:ValidatePolicy).
  validateWithAws: bool(env.AWS_VALIDATE_POLICY, false),

  oidc: {
    issuer: env.OIDC_ISSUER || '',
    clientId: env.OIDC_CLIENT_ID || '',
    clientSecret: env.OIDC_CLIENT_SECRET || '',
    groupsClaim: env.OIDC_GROUPS_CLAIM || 'groups',
    scopes: env.OIDC_SCOPES || 'openid profile email groups',
  },

  approvalWebhookUrl: env.APPROVAL_WEBHOOK_URL || '',
  allowedEmailDomains: list(env.ALLOWED_EMAIL_DOMAINS || '', ''),
};

export const oidcEnabled = () => Boolean(config.oidc.issuer && config.oidc.clientId && config.oidc.clientSecret);

export function assertConfig() {
  if (config.env === 'production') {
    if (config.sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters in production');
    if (config.dataEncryptionKey.length < 32) throw new Error('DATA_ENCRYPTION_KEY must be at least 32 characters in production');
  }
}
