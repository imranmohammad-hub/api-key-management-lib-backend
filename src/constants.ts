
// Library constants
export const KEY_MANAGER_LIB_VERSION = '1.0.0';

// Injection Token for the DataSource
export const LIB_DATA_SOURCE_TOKEN = 'LIB_DATA_SOURCE';

export const SUPPORTED_FEATURES = [
  'key-generation',
  'key-validation', 
  'key-revocation',
  'key-listing',
  'permission-checking',
  'pagination',
  'audit-logging',
  'request-tracking',
] as const;

export const DEFAULT_CONFIG = {
  DEFAULT_PAGE_SIZE: 50,
  MAX_PAGE_SIZE: 100,
  DEFAULT_KEY_EXPIRY_MS: 365 * 24 * 60 * 60 * 1000,
  KEY_PREFIX: 'ak_',
  KEY_ENTROPY_BYTES: 32,
} as const;
