import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import pino from 'pino';
import { config } from '../config.js';

// FR7: every allow/block decision must log attack category, source IP,
// endpoint, latency. Logs are structured JSON on stdout by default; when
// LOG_FILE is set (see docker-compose's armourapi volume + ops/filebeat.yml),
// also written to that file so Filebeat can tail it and ship to the ELK
// stack per the doc's "pino -> ELK stack" tooling choice - ArmourAPI itself
// never talks to Elasticsearch directly, it just needs to log to a path
// something else can read.
function createLogger() {
  const stdoutStream = { stream: process.stdout };
  if (!config.logFile) {
    return pino({ level: config.logLevel }, stdoutStream.stream);
  }

  mkdirSync(dirname(config.logFile), { recursive: true });
  const fileStream = pino.destination({ dest: config.logFile, mkdir: true });
  const streams = pino.multistream([stdoutStream, { stream: fileStream }]);
  return pino({ level: config.logLevel }, streams);
}

export const logger = createLogger();

export function logDecision({ ip, method, url, decision, category, latencyMs, scanner }) {
  logger.info({ ip, method, url, decision, category, latencyMs, scanner }, 'armourapi_decision');
}
