export const config = {
  port: Number(process.env.PORT || 8080),
  logLevel: process.env.LOG_LEVEL || 'info',
  logFile: process.env.LOG_FILE || null, // e.g. logs/armourapi.log - see src/logging/logger.js
  targets: {
    juiceShop: process.env.JUICE_SHOP_URL || 'http://localhost:3000',
    dvga: process.env.DVGA_URL || 'http://localhost:5013',
    androgoat: process.env.ANDROGOAT_URL || 'http://localhost:5000',
  },
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwt: {
    secret: process.env.JWT_SECRET || 'change-me',
    accessTtl: process.env.JWT_ACCESS_TTL || '15m',
  },
  // Shared-secret gate for ArmourAPI's own admin/security API (ARM-01 audit
  // finding: these routes had zero auth - anyone reaching the gateway could
  // write arbitrary blocklist entries or read live threat data). A single
  // header check is enough for this project's scope - no need for a second
  // full auth system alongside the gateway-session JWTs above.
  adminApiKey: process.env.ADMIN_API_KEY || 'change-me-admin-key',
};
