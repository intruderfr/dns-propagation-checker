# dns-propagation-checker

Check DNS propagation of a record across dozens of public resolvers worldwide — then exit clean when everything agrees.

Useful any time you're changing DNS and need to know when the change is actually live everywhere, not just on your laptop.

- Changing nameservers or domain registrar
- Cutting over an A/AAAA record to a new host
- Rotating MX records
- Publishing TXT records for SPF / DKIM / DMARC
- Adding or modifying CAA records

## Features

- Queries **18 public resolvers** out of the box (Google, Cloudflare, Quad9, OpenDNS, AdGuard, Yandex, Hurricane Electric, DNS.WATCH, and more)
- Parallel queries with per-resolver timeout and RTT measurement
- Automatic **consensus detection** — flags resolvers that disagree with the majority
- **Watch mode** polls until the record has fully propagated (or a max-wait timeout trips)
- `--expect` mode validates that every resolver returns a specific value — perfect for CI / scripted cutovers
- Machine-readable `--json` output
- Supports `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `CAA`, `SOA`, `PTR`, `SRV`
- Zero config, single dependency (`dnspython`)

## Install

```bash
pip install dnspython
git clone https://github.com/intruderfr/dns-propagation-checker.git
cd dns-propagation-checker
python dns_propagation_checker.py --help
```

Or drop `dns_propagation_checker.py` anywhere on your `PATH` and make it executable.

## Usage

Check the A record for a domain:

```bash
python dns_propagation_checker.py example.com
```

Check a specific record type:

```bash
python dns_propagation_checker.py example.com -t MX
python dns_propagation_checker.py example.com -t TXT
python dns_propagation_checker.py _dmarc.example.com -t TXT
```

**Watch mode** — poll every 30s until every resolver returns the same answer:

```bash
python dns_propagation_checker.py example.com --watch 30 --max-wait 1800
```

**Expect mode** — fail the script if any resolver is missing the expected value. Handy in CI pipelines that wait for DNS before the next deploy step:

```bash
python dns_propagation_checker.py example.com \
  --expect 203.0.113.42 \
  --watch 15 --max-wait 900
```

**JSON output** for automation:

```bash
python dns_propagation_checker.py example.com --json > report.json
```

**Custom resolver list:**

```bash
python dns_propagation_checker.py example.com \
  --resolvers 1.1.1.1,8.8.8.8,9.9.9.9
```

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | All resolvers agree (and `--expect` values found, if provided)       |
| 1    | `--expect` value not returned by every resolver                      |
| 2    | Mismatch or errors detected (single-run mode)                        |
| 3    | `--max-wait` exceeded in `--watch` mode                              |

## Example output

```
DNS Propagation Report
  Domain : example.com
  Type   : A
  Checked: 18 resolvers

RESOLVER         IP                PROVIDER      REG     TTL     RTT  VALUES
----------------------------------------------------------------------------
Google-1         8.8.8.8           Google        Global    300    22ms  93.184.216.34
Cloudflare-1     1.1.1.1           Cloudflare    Global    300    18ms  93.184.216.34
Quad9            9.9.9.9           Quad9         Global    300    31ms  93.184.216.34
...

✓ Fully propagated — all 18 resolvers agree.
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).

## Author

**Aslam Ahamed** — Head of IT @ Prestige One Developments, Dubai
[LinkedIn](https://www.linkedin.com/in/aslam-ahamed/)
