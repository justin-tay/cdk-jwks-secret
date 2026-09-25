// Tests must never reach AWS: replace whatever credentials the environment has
// with fake ones, so an unmocked SDK call fails instead of using a real account.
for (const name of ['AWS_PROFILE', 'AWS_SESSION_TOKEN', 'AWS_CONTAINER_CREDENTIALS_FULL_URI']) {
  delete process.env[name];
}
process.env.AWS_ACCESS_KEY_ID = 'test';
process.env.AWS_SECRET_ACCESS_KEY = 'test';
process.env.AWS_REGION = 'us-east-1';
process.env.AWS_EC2_METADATA_DISABLED = 'true';
