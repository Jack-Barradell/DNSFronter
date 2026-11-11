# DNSFronter

## Overview

A simple tool that acts as a proxy DNS server for situations where you have an upstream program handling DNS but wish to insert some specific records. For example, making use of a tool such as Evilginx2 but wishing to assign additional DNS records beyond those defined in your phishlets.

Queries that match a record in records.txt are answered locally, everything else is forwarded to the upstream server. If the upstream server doesn't respond the client gets a SERVFAIL.

## Usage

```
pip install -r requirements.txt
sudo python3 dnsfronter.py
```

Binding to port 53 needs root. Every option apart from `--allowlist` has a default, and the defaults can also be changed at the top of dnsfronter.py.

| Option | Default | Description |
|--------|---------|-------------|
| `--upstream HOST[:PORT]` | `1.1.1.1:53` | Upstream DNS server, use `[ADDRESS]:PORT` for IPv6 |
| `--bind ADDRESS` | `0.0.0.0` | Address to listen on, give it more than once to listen on several (e.g. `--bind 0.0.0.0 --bind ::`) |
| `--port PORT` | `53` | Port to listen on |
| `--records FILE` | `records.txt` | Records file |
| `--denylist FILE` | `denylist.txt` | Clients that never get an answer |
| `--allowlist FILE` | none | If given, only clients in this file get an answer |
| `--timeout SECONDS` | `5` | How long to wait for the upstream server |
| `--no-tcp` | off | Only listen on UDP |
| `--quiet` / `--verbose` | off | Only log problems / also log answers and upstream timings |

IPv6 upstreams with a port need brackets, e.g. `--upstream [::1]:5353`. Without them `::1:5353` is read as a different IPv6 address on port 53, because `::1:5353` is a valid address on its own.

When fronting something that also wants port 53, such as Evilginx2, move that program to another port and point the upstream at it:

```
sudo python3 dnsfronter.py --upstream 127.0.0.1:5353
```

On Ubuntu, systemd-resolved already uses port 53. Free it by setting `DNSStubListener=no` in `/etc/systemd/resolved.conf`, running `sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf` so the server's own DNS keeps working, then restarting systemd-resolved.

## Records

Records go in records.txt, one per line, as `<Type> <Full Name> <Value> <TTL> <Extras>`. Supported types are A, AAAA, CNAME, TXT, NS, PTR, MX, SRV, CAA and SOA. See the examples at the top of records.txt.

Most types only need a value. The ones with extras take them after the TTL:

| Type | Value | Extras | Example |
|------|-------|--------|---------|
| MX | Mail server | `[priority]`, default 10 | `MX example.com mail.example.com 3600 10` |
| SRV | Target host | `<priority> <weight> <port>`, all required | `SRV _sip._tcp.example.com sip.example.com 3600 10 5 5060` |
| CAA | CA domain or iodef URL | `[tag] [flags]`, default `issue 0` | `CAA example.com letsencrypt.org 3600 issuewild 0` |
| SOA | Primary name server | `<rname> [serial refresh retry expire minimum]`, defaults `1 7200 3600 1209600 300` | `SOA example.com ns1.example.com 3600 hostmaster.example.com 2026111101` |

CAA extras are tag then flags, the other way round to a zone file, so the flags can be left off.

- Names are full domain names, the trailing dot is optional
- Values with spaces can be wrapped in quotes or use `\s` for each space
- Long TXT values such as DKIM keys are split into 255 byte strings automatically
- A name starting with `*.` is a wildcard. An exact name always wins over a wildcard, and the most specific wildcard wins over less specific ones
- A CNAME answers any query type for its name. If the target is also in records.txt, its records are included in the same answer
- If a name exists locally but not with the type being asked for, the query is forwarded upstream

## Deny and allow lists

denylist.txt and the optional allow list take one IP address or CIDR range per line, e.g. `192.0.2.10` or `198.51.100.0/24`. Lines starting with `#` are ignored. The deny list always wins.

The allow list is opt in with `--allowlist` and only applies while it has at least one entry. If the file is missing or empty, all clients are answered (apart from denied ones) and a warning is logged.

## Reloading

records.txt and both lists are checked for changes every couple of seconds and reloaded automatically. A reload can also be forced with `kill -HUP <pid>`. If records.txt can't be read during a reload, the current records are kept.

## TCP

The server listens on TCP as well as UDP. Local answers too big for UDP are sent truncated so the client retries over TCP, and queries that arrive over TCP are forwarded upstream over TCP.

## Requirements

- Python 3.8 or newer
- dnslib (see requirements.txt)
