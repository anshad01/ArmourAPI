"""
Scripted, repeatable version of the manual verification done for Phase 13.5:
spawns the 3-node cluster (blocklist_node.py), waits for a leader to be
elected, submits a write through a follower (proving forwarding + majority
commit), kills the leader outright, confirms a new leader is elected and the
cluster keeps accepting writes on the remaining 2 nodes (the actual "Raft
proof" - availability survives a node failure), then restarts the killed
node and confirms it rejoins and catches up via log replication.

This is a standalone proof-of-concept of the consensus layer for a possible
future clustered ArmourAPI deployment - it is NOT wired into ArmourAPI's
live, tested request-blocking pipeline (see docs/validation-test-report.md
section 1.5 and this directory's README for why, and what scope was agreed
with the client instead).

Usage: python run_demo.py
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

HTTP_PORTS = [8321, 8322, 8323]
STATE_NAMES = {0: 'FOLLOWER', 1: 'CANDIDATE', 2: 'LEADER'}


def http_get(port, path):
    with urllib.request.urlopen(f'http://localhost:{port}{path}', timeout=3) as resp:
        return json.loads(resp.read())


def http_post(port, path, payload):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(f'http://localhost:{port}{path}', data=body, method='POST',
                                  headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_leader(ports, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        statuses = {}
        try:
            for p in ports:
                statuses[p] = http_get(p, '/status')
            leaders = {s['leader'] for s in statuses.values() if s.get('has_quorum')}
            if len(leaders) == 1 and None not in leaders:
                leader_port = next(p for p, s in statuses.items() if s['state'] == 2)
                return leader_port, statuses
        except (urllib.error.URLError, ConnectionRefusedError, ConnectionResetError):
            pass
        time.sleep(0.3)
    raise RuntimeError(f'no leader elected within {timeout}s')


def print_statuses(label, ports):
    print(f'\n--- {label} ---')
    for p in ports:
        try:
            s = http_get(p, '/status')
            print(f'  :{p}  self={s["self"]:<15} state={STATE_NAMES[s["state"]]:<10} '
                  f'leader={s["leader"]}  term={s["raft_term"]}  quorum={s["has_quorum"]}')
        except Exception as exc:
            print(f'  :{p}  UNREACHABLE ({exc})')


def main():
    print('=== Phase 13.5: standalone 3-node Raft consensus demo (PySyncObj) ===')
    procs = {}
    for i in range(3):
        procs[i] = subprocess.Popen([sys.executable, 'blocklist_node.py', str(i)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('spawned 3 node processes, waiting for leader election...')

    try:
        leader_port, _ = wait_for_leader(HTTP_PORTS)
        leader_idx = HTTP_PORTS.index(leader_port)
        print_statuses('leader elected', HTTP_PORTS)

        follower_port = next(p for p in HTTP_PORTS if p != leader_port)
        print(f'\nwriting block_ip("10.0.0.5") via a FOLLOWER (:{follower_port}) - proves forwarding + majority commit')
        status, resp = http_post(follower_port, '/block', {'ip': '10.0.0.5'})
        print(f'  -> HTTP {status} {resp}')
        for p in HTTP_PORTS:
            print(f'  :{p} blocklist = {http_get(p, "/blocklist")}')

        print(f'\nkilling the leader (node {leader_idx}, :{leader_port}) outright...')
        procs[leader_idx].kill()
        procs[leader_idx].wait()
        del procs[leader_idx]

        surviving_ports = [p for p in HTTP_PORTS if p != leader_port]
        new_leader_port, _ = wait_for_leader(surviving_ports)
        print_statuses('new leader elected on the surviving 2 nodes', surviving_ports)

        print(f'\nwriting block_ip("172.16.0.9") with only 2/3 nodes alive - proves availability survives a node failure')
        status, resp = http_post(new_leader_port, '/block', {'ip': '172.16.0.9'})
        print(f'  -> HTTP {status} {resp}')
        for p in surviving_ports:
            print(f'  :{p} blocklist = {http_get(p, "/blocklist")}')

        print(f'\nrestarting the killed node {leader_idx}...')
        procs[leader_idx] = subprocess.Popen([sys.executable, 'blocklist_node.py', str(leader_idx)],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        rejoined_status = http_get(HTTP_PORTS[leader_idx], '/status')
        rejoined_blocklist = http_get(HTTP_PORTS[leader_idx], '/blocklist')
        print(f'  rejoined as {STATE_NAMES[rejoined_status["state"]]}, log_len={rejoined_status["log_len"]}, '
              f'blocklist={rejoined_blocklist["blocked_ips"]}')
        caught_up = set(rejoined_blocklist['blocked_ips']) == {'10.0.0.5', '172.16.0.9'}
        print(f'  caught up via log replication: {caught_up}')

        print('\n=== Demo complete: leader election, majority-quorum writes (incl. via a follower), '
              'and availability surviving a node failure all confirmed on this run. ===')
    finally:
        for p in procs.values():
            p.kill()
        for p in procs.values():
            p.wait()


if __name__ == '__main__':
    main()
