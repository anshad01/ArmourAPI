"""
One Raft node in the standalone 3-node consensus proof-of-concept (Phase 13.5,
Parameters.rtf.doc's "Inclusion of Raft Consensus" section). Deliberately
outside src/ and never imported by ArmourAPI - this demonstrates the
consensus layer itself, decoupled from the tested/pushed gateway, per the
scope agreed with the client (standalone, 3 nodes not the doc's 5).

Replicates a toy blocklist (a set of "blocked IPs") - small stand-in for
what a real clustered ArmourAPI deployment would actually replicate (the
same shape of data as src/rate-limiter/blocklist.js's block()/isBlocked(),
just replicated via Raft log consensus instead of Redis).

Each node also runs a tiny local HTTP control API (not part of Raft itself)
so run_demo.py, running as a separate process, can drive it: query status,
issue a write, or read the locally-applied state.

Usage: python blocklist_node.py <node_index 0-2>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from pysyncobj import SyncObj, SyncObjConf, replicated

# 3 nodes on localhost, distinct Raft ports and distinct HTTP control ports.
RAFT_NODES = ['localhost:4321', 'localhost:4322', 'localhost:4323']
HTTP_PORTS = [8321, 8322, 8323]


class ReplicatedBlocklist(SyncObj):
    def __init__(self, self_node, other_nodes):
        # No journalFile/fullDumpFile - in-memory only, on purpose. This demo
        # is about the consensus mechanics (election, quorum, availability),
        # not durable-restart semantics, which the doc's own section doesn't
        # ask for either.
        conf = SyncObjConf(autoTick=True)
        super(ReplicatedBlocklist, self).__init__(self_node, other_nodes, conf)
        self.__blocked_ips = set()

    @replicated
    def block_ip(self, ip):
        self.__blocked_ips.add(ip)

    @replicated
    def unblock_ip(self, ip):
        self.__blocked_ips.discard(ip)

    def get_blocked_ips(self):
        # Local read of this node's own applied state - not itself a
        # replicated operation (matches the real ArmourAPI blocklist's own
        # isBlocked() being a plain local read against replicated state).
        return sorted(self.__blocked_ips)


def make_handler(syncobj):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, payload):
            body = json.dumps(payload).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/status':
                status = syncobj.getStatus()
                leader = status.get('leader')
                self._send(200, {
                    'self': str(status.get('self')),
                    'state': status.get('state'),  # 0=FOLLOWER, 1=CANDIDATE, 2=LEADER
                    'leader': str(leader) if leader else None,
                    'has_quorum': status.get('has_quorum'),
                    'raft_term': status.get('raft_term'),
                    'log_len': status.get('log_len'),
                })
            elif self.path == '/blocklist':
                self._send(200, {'blocked_ips': syncobj.get_blocked_ips()})
            else:
                self._send(404, {'error': 'not found'})

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            try:
                body = json.loads(self.rfile.read(length) or b'{}')
            except json.JSONDecodeError:
                self._send(400, {'error': 'invalid json'})
                return

            if self.path == '/block':
                try:
                    syncobj.block_ip(body['ip'], sync=True, timeout=5)
                    self._send(200, {'ok': True})
                except Exception as exc:  # SyncObjException on no-quorum/timeout
                    self._send(503, {'ok': False, 'error': str(exc)})
            else:
                self._send(404, {'error': 'not found'})

        def log_message(self, *args):
            pass  # quiet - run_demo.py polls /status frequently

    return Handler


def main():
    idx = int(sys.argv[1])
    self_node = RAFT_NODES[idx]
    other_nodes = [n for i, n in enumerate(RAFT_NODES) if i != idx]

    syncobj = ReplicatedBlocklist(self_node, other_nodes)

    httpd = HTTPServer(('localhost', HTTP_PORTS[idx]), make_handler(syncobj))
    print(f'node {idx} ({self_node}) up - control API on :{HTTP_PORTS[idx]}', flush=True)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
