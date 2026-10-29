# Evidence: the stalled etcd peer stream of keel#167, in the netns harness

Date: 2026-10-15. Host: the dev host (Debian 13, kernel 6.12, etcd
3.5.16), not the real nodes. BR3-THIN is offline.

## Set-up

The nodes, links and etcd of `tests/etcd_netns.py`: 3 members in 3
network namespaces, WireGuard, keel's rendered etcd configuration, links
of 250 ms ±25 ms with 2% loss on each leg. A script of the session
imports that harness and runs 12 rounds. Each round cuts the current
leader (100% loss both ways) for 40 s, heals it, and waits 25 s. Each
second it records each member's leader and term, and `ss -tinoH` of
every connection to or from port 2380.

```
sudo -n unshare -n env PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONPATH=<keel>:<keel>/tests python3 cuts.py <out> 12 40
# run 2 only: RETRIES2=5 sets net.ipv4.tcp_retries2=5 in each namespace
```

## Results

`elected` is the time from the cut to a new leader that both other
members report. `back` is the time from the heal to all 3 members
healthy with one leader.

| Round | Cut | Run 1, default 15: elected s | back s | Run 2, tcp_retries2 5: elected s | back s |
| --- | --- | --- | --- | --- | --- |
| 0 | A / A | 11.0 | 26.0 | 13.0 | 13.0 |
| 1 | C / C | 9.0 | 30.1 | 12.0 | 14.0 |
| 2 | B / B | 28.0 | 61.2 | 10.0 | 11.0 |
| 3 | A / C | 11.0 | 24.1 | 8.0 | 11.0 |
| 4 | B / B | 13.0 | 30.2 | 12.0 | 13.1 |
| 5 | C / A | 10.0 | 29.2 | 9.0 | 11.1 |
| 6 | A / C | no leader in 40 s | 24.2 | 10.0 | 16.1 |
| 7 | B / A | 11.1 | 29.2 | 13.0 | 10.1 |
| 8 | C / C | 9.1 | 24.2 | 11.1 | 9.1 |
| 9 | A / B | 12.1 | 29.3 | 9.0 | 13.1 |
| 10 | B / A | 11.1 | 30.3 | 11.1 | 8.1 |
| 11 | C / B | 11.1 | 28.3 | 9.1 | 14.1 |

Highest TCP backoff seen on a peer connection, count of samples:

| Run | backoff 0 to 4 | 5 | 6 | 7 | 8 |
| --- | --- | --- | --- | --- | --- |
| 1 | 35910 | 2232 | 3803 | 137 | 112 |
| 2 | 16479 | 0 | 0 | 0 | 0 |

## The mechanism, run 1, round 2

Round 1 cut C from 1792097156.9 to 1792097196.9. Round 2 cut B at
1792097253.0, with A and C left. In C's namespace, the connection
`[fd00:6b65:e7c::3]:2380 <- [fd00:6b65:e7c::1]:36006` stayed
established with backoff 6, then 7, and an RTO of 58 368 ms. Its send
queue grew from 4347 to 8343 bytes between 56 s after the round 1 heal
and 21 s into round 2: etcd went on writing to it. The retransmission
at about 23 s into round 2 delivered the queue (send queue 169, backoff
0 at 25.2 s), and the new leader came at 28.0 s. A's side of that
connection had closed during the cut, and its FIN was lost in the cut.

This is what the real nodes showed in keel#167: the witness got none
of 9054's messages during the cut, and then a burst of old ones after
the heal.

## The etcd netns test, before and after the fix

`tests/test_etcd_netns.py` on the dev host:

| Commit | Result | rejoined_s | new_leader_s | highest backoff |
| --- | --- | --- | --- | --- |
| test only | 2 failed, 6 passed | 20.0 | 9.0 | A 8, B 7, C 8 |
| test and fix | 8 passed | 6.0 | 12.0 | 4 on each |

CI before the fix, the etcd job, runs 2 to 88: `rejoined_s` 19.1 to
51.2 in all 33 runs; `new_leader_s` 48.2 to 51.2 in 8 of 33 runs.
