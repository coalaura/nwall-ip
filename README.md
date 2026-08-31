# nwall_ip

Companion tool for [coalaura/nwall](https://github.com/coalaura/nwall): nwall hard-closes matching requests (logged as status `444`); nwall_ip scans the Nginx access logs in `/var/log/nginx`, scores client IPs by their rejected requests and requested paths, and blocks repeat offenders on ports 80/443 at the firewall level via ipset and iptables. State is persisted between runs so only new log lines are counted.

## Usage

```
nwall_ip          # scan logs and apply firewall rules
nwall_ip remove   # remove all nwall firewall rules and sets
```

Run it from a directory containing `config.yml` (see `example.config.yml`).

## Configuration

```yaml
whitelist:
  ips:                 # never blocked
    - 1.2.3.4
  urls:                # fetched each run; lists of IPs
    - https://api.example.com/ips

access_log:
  format: ...          # optional; defaults to Nginx's combined format.
                       # must contain $remote_addr, $time_local, $request, $status

path_rules:            # score points per matching request path
  - match: contains    # startswith | endswith | contains
    pattern: /wp-
    score: 4
```

## Scoring

- Each request matching a path rule adds its score.
- Each `444` response (an nwall drop) adds 1.
- IPs reaching a total score of 10 that are not whitelisted get blocked.

## State

Results are written to `nwall_ip.log` next to the executable (header with timestamp, cursor and total score, followed by per-IP entries). Delete the file to rescan everything from scratch.
