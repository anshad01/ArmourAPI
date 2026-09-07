import { EventEmitter } from 'node:events';

// In-process pub/sub feeding GET/WS /api/v1/security/traffic ("live-stream
// traffic map ... useful for demoing"). Every request decision (allow or
// block) is published here; each connected WS client subscribes and gets
// forwarded events until it disconnects.
const bus = new EventEmitter();
bus.setMaxListeners(0); // unbounded number of WS subscribers

export function publishTraffic(event) {
  bus.emit('traffic', { timestamp: Date.now(), ...event });
}

export function subscribeTraffic(handler) {
  bus.on('traffic', handler);
  return () => bus.off('traffic', handler);
}
