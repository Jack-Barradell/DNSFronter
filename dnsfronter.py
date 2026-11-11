from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE, EDNS0, A, AAAA, CNAME, TXT, NS, PTR, MX, SRV, CAA, SOA
import argparse
import asyncio
import ipaddress
import logging
import os
import shlex
import signal
import socket
import struct
import time

UPSTREAM_SERVER = "1.1.1.1"
UPSTREAM_PORT = 53
UPSTREAM_TIMEOUT = 5
BIND_IP = "0.0.0.0"
BIND_PORT = 53

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(BASE_DIR, "records.txt")
DENYLIST_FILE = os.path.join(BASE_DIR, "denylist.txt")

RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "NS", "PTR", "MX", "SRV", "CAA", "SOA"]
SOA_TIMES = [("serial", 1), ("refresh", 7200), ("retry", 3600), ("expire", 1209600), ("minimum", 300)]
MAX_TTL = 2147483647
MAX_SHORT = 65535
MAX_LONG = 4294967295
MAX_CNAME_CHAIN = 8
UDP_PAYLOAD_SIZE = 1232
TCP_IDLE_TIMEOUT = 10
WATCH_INTERVAL = 2

log = logging.getLogger("dnsfronter")


class RecordError(Exception):
    pass


def parse_address(text, default_port):
    host = text
    port = default_port

    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
    elif text.count(":") == 1:
        host, port = text.split(":")

    host = str(ipaddress.ip_address(host))
    port = int(port)
    if not 0 < port <= MAX_SHORT:
        raise ValueError("port {} is out of range".format(port))

    return host, port


def format_address(host, port):
    if ":" in host:
        return "[{}]:{}".format(host, port)
    return "{}:{}".format(host, port)


def family_of(host):
    if ipaddress.ip_address(host).version == 6:
        return socket.AF_INET6
    return socket.AF_INET


def client_address(client_ip):
    address = ipaddress.ip_address(client_ip.split("%")[0])
    if address.version == 6 and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def forwards_to_itself(upstream, bind_addresses, bind_port):
    host, port = upstream
    if port != bind_port:
        return False

    address = ipaddress.ip_address(host)
    for bind in bind_addresses:
        if host == bind:
            return True
        if bind == "0.0.0.0" and address.version == 4 and address.is_loopback:
            return True
        if bind == "::" and address.version == 6 and address.is_loopback:
            return True

    return False


def normalise_name(name):
    return str(name).rstrip(".").lower()


def parse_number(text, maximum):
    try:
        number = int(text)
    except ValueError:
        return None

    if 0 <= number <= maximum:
        return number
    return None


def extra_number(extras, index, maximum, default, label):
    if index >= len(extras):
        if default is None:
            raise RecordError("{} is missing".format(label))
        return default

    number = parse_number(extras[index], maximum)
    if number is None:
        raise RecordError("{} is not a whole number between 0 and {}".format(label, maximum))
    return number


def split_line(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    return list(lexer)


def build_rdata(record_type, value, extras):
    if record_type == "A":
        return A(value)
    elif record_type == "AAAA":
        return AAAA(value)
    elif record_type == "CNAME":
        return CNAME(value)
    elif record_type == "TXT":
        data = value.encode()
        return TXT([data[i:i + 255] for i in range(0, len(data), 255)] or [b""])
    elif record_type == "NS":
        return NS(value)
    elif record_type == "PTR":
        return PTR(value)
    elif record_type == "MX":
        return MX(value, extra_number(extras, 0, MAX_SHORT, 10, "MX priority"))
    elif record_type == "SRV":
        priority = extra_number(extras, 0, MAX_SHORT, None, "SRV priority")
        weight = extra_number(extras, 1, MAX_SHORT, None, "SRV weight")
        port = extra_number(extras, 2, MAX_SHORT, None, "SRV port")
        return SRV(priority, weight, port, value)
    elif record_type == "CAA":
        tag = extras[0] if extras else "issue"
        if not tag.isalnum():
            raise RecordError("CAA tag \"{}\" can only contain letters and numbers".format(tag))
        return CAA(extra_number(extras, 1, 255, 0, "CAA flags"), tag, value)
    elif record_type == "SOA":
        if not extras:
            raise RecordError("SOA rname is missing")
        times = []
        for index, (label, default) in enumerate(SOA_TIMES, start=1):
            times.append(extra_number(extras, index, MAX_LONG, default, "SOA " + label))
        return SOA(value, extras[0], times)


def parse_record(line):
    try:
        split = split_line(line)
    except ValueError:
        return None, "it has a quote that is never closed"

    if len(split) < 4:
        return None, "it does not meet the expected format"

    record_type = split[0].upper()
    if record_type not in RECORD_TYPES:
        return None, "record type \"{}\" is not one of {}".format(split[0], ", ".join(RECORD_TYPES))

    ttl = parse_number(split[3], MAX_TTL)
    if ttl is None:
        return None, "TTL is not a whole number between 0 and {}".format(MAX_TTL)

    name = normalise_name(split[1])
    value = split[2].replace(r"\s", " ")
    qtype = getattr(QTYPE, record_type)

    try:
        rdata = build_rdata(record_type, value, split[4:])
        DNSRecord(rr=[RR(name, qtype, rdata=rdata, ttl=ttl)]).pack()
    except RecordError as e:
        return None, str(e)
    except Exception as e:
        return None, "the name or value is not valid ({})".format(e)

    record = {
        "name": name,
        "type": record_type,
        "qtype": qtype,
        "rdata": rdata,
        "ttl": ttl,
    }

    if record_type == "CNAME":
        record["target"] = normalise_name(value)

    return record, None


def load_records(path):
    records = {}
    loaded = 0
    didnt_load = 0

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            record, error = parse_record(line)
            if error:
                log.warning("[!] Could not load record \"%s\" as %s", line, error)
                didnt_load += 1
                continue

            records.setdefault(record["name"], []).append(record)
            loaded += 1

    log.info("[+] Loaded %s records", loaded)

    if didnt_load > 0:
        log.warning("[-] Didn't load %s records", didnt_load)

    warn_about_cname_conflicts(records)
    return records


def warn_about_cname_conflicts(records):
    for name, entries in sorted(records.items()):
        if len(entries) > 1 and any(entry["type"] == "CNAME" for entry in entries):
            log.warning("[-] %s has a CNAME record, any other records for it will be ignored", name)


def lookup(records, name):
    if name in records:
        return records[name]

    labels = name.split(".")
    for i in range(1, len(labels)):
        wildcard = "*." + ".".join(labels[i:])
        if wildcard in records:
            return records[wildcard]

    return []


def find_answers(records, qname, qtype):
    answers = []
    seen = set()
    owner = str(qname)

    while len(seen) < MAX_CNAME_CHAIN:
        name = normalise_name(owner)
        if name in seen:
            break
        seen.add(name)

        matches = lookup(records, name)
        cnames = [record for record in matches if record["type"] == "CNAME"]

        if not cnames:
            for record in matches:
                if qtype == "ANY" or record["type"] == qtype:
                    answers.append((owner, record))
            break

        answers.append((owner, cnames[0]))
        if qtype == "CNAME":
            break
        owner = cnames[0]["target"]

    return answers


def load_networks(path, label):
    networks = []

    if not path or not os.path.exists(path):
        return networks

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                log.warning("[!] Ignoring %s entry \"%s\" as it is not an IP address or CIDR range", label, line)

    return networks


def make_reply(request, aa):
    header = DNSHeader(id=request.header.id, qr=1, aa=aa, ra=1, rd=request.header.rd)
    return DNSRecord(header, q=request.q)


def edns_size(request):
    for record in request.ar:
        if record.rtype == QTYPE.OPT:
            return record.rclass
    return None


def pack_reply(request, reply, tcp):
    client_size = edns_size(request)
    if client_size is not None:
        reply.add_ar(EDNS0(udp_len=UDP_PAYLOAD_SIZE))

    packed = reply.pack()
    limit = 512 if client_size is None else min(max(client_size, 512), UDP_PAYLOAD_SIZE)
    if tcp or len(packed) <= limit:
        return packed

    truncated = make_reply(request, aa=reply.header.aa)
    truncated.header.tc = 1
    if client_size is not None:
        truncated.add_ar(EDNS0(udp_len=UDP_PAYLOAD_SIZE))
    return truncated.pack()


class Fronter:
    def __init__(self, args):
        self.upstream = args.upstream
        self.upstream_family = family_of(args.upstream[0])
        self.timeout = args.timeout
        self.records_file = args.records
        self.denylist_file = args.denylist
        self.allowlist_file = args.allowlist
        self.records = {}
        self.deny_list = []
        self.allow_list = []

    def watched_files(self):
        return [path for path in (self.records_file, self.denylist_file, self.allowlist_file) if path]

    def reload(self, reason=None):
        if reason:
            log.info("[+] Reloading, %s", reason)

        try:
            self.records = load_records(self.records_file)
        except OSError as e:
            log.error("[!] Could not read records, keeping the current ones: %s", e)

        self.deny_list = load_networks(self.denylist_file, "deny list")
        if self.deny_list:
            log.info("[+] Loaded %s deny list entries", len(self.deny_list))

        if self.allowlist_file:
            self.allow_list = load_networks(self.allowlist_file, "allow list")
            if self.allow_list:
                log.info("[+] Loaded %s allow list entries", len(self.allow_list))
            else:
                log.warning("[-] Allow list %s is missing or empty, answering all clients", self.allowlist_file)

    def is_allowed(self, client_ip):
        address = client_address(client_ip)

        if any(address in network for network in self.deny_list):
            return False

        if self.allow_list:
            return any(address in network for network in self.allow_list)

        return True

    async def resolve(self, data, client_ip, tcp):
        if not self.is_allowed(client_ip):
            log.info("[-] Didn't answer request from %s", client_ip)
            return None

        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            log.warning("[!] Could not parse request from %s: %s", client_ip, e)
            return None

        qtype = QTYPE[request.q.qtype]
        log.info("[+] Query from %s: %s %s", client_ip, normalise_name(request.q.qname), qtype)

        answers = find_answers(self.records, request.q.qname, qtype)
        if answers:
            reply = make_reply(request, aa=1)
            for owner, record in answers:
                reply.add_answer(RR(owner, record["qtype"], rdata=record["rdata"], ttl=record["ttl"]))
                log.debug("[+]   %s %s %s %s", normalise_name(owner), record["ttl"], record["type"], record["rdata"])

            log.info("[+] Returned %s local record(s) to %s", len(answers), client_ip)
            return pack_reply(request, reply, tcp)

        response = await self.forward(data, tcp)
        if response:
            log.info("[+] Returned upstream response to %s", client_ip)
            return response

        reply = make_reply(request, aa=0)
        reply.header.rcode = RCODE.SERVFAIL
        log.warning("[!] Sent SERVFAIL to %s", client_ip)
        return pack_reply(request, reply, tcp)

    async def forward(self, data, tcp):
        protocol = "TCP" if tcp else "UDP"
        send = self.forward_tcp if tcp else self.forward_udp
        started = time.monotonic()

        try:
            response = await asyncio.wait_for(send(data), timeout=self.timeout)
        except asyncio.TimeoutError:
            log.error("[!] Upstream server didn't respond over %s within %g seconds", protocol, self.timeout)
            return None
        except Exception as e:
            log.error("[!] Error forwarding to upstream over %s: %s", protocol, e)
            return None

        log.debug("[+] Upstream answered over %s in %.0fms", protocol, (time.monotonic() - started) * 1000)
        return response

    async def forward_udp(self, data):
        loop = asyncio.get_running_loop()
        sock = socket.socket(self.upstream_family, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            sock.connect(self.upstream)
            await loop.sock_sendall(sock, data)
            return await loop.sock_recv(sock, 65535)
        finally:
            sock.close()

    async def forward_tcp(self, data):
        reader, writer = await asyncio.open_connection(*self.upstream)

        try:
            writer.write(struct.pack("!H", len(data)) + data)
            await writer.drain()
            length = struct.unpack("!H", await reader.readexactly(2))[0]
            return await reader.readexactly(length)
        finally:
            writer.close()


class UDPHandler(asyncio.DatagramProtocol):
    def __init__(self, fronter):
        self.fronter = fronter
        self.transport = None
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        task = asyncio.create_task(self.handle(data, addr))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, data, addr):
        try:
            response = await self.fronter.resolve(data, addr[0], tcp=False)
            if response:
                self.transport.sendto(response, addr)
        except Exception as e:
            log.error("[!] Encountered exception handling request from %s: %s", addr[0], e)


async def handle_tcp(fronter, reader, writer):
    client_ip = writer.get_extra_info("peername")[0]

    try:
        while True:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=TCP_IDLE_TIMEOUT)
            length = struct.unpack("!H", header)[0]
            data = await asyncio.wait_for(reader.readexactly(length), timeout=TCP_IDLE_TIMEOUT)

            response = await fronter.resolve(data, client_ip, tcp=True)
            if response is None:
                break

            writer.write(struct.pack("!H", len(response)) + response)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    except Exception as e:
        log.error("[!] Encountered exception handling TCP request from %s: %s", client_ip, e)
    finally:
        writer.close()


def file_state(paths):
    state = []
    for path in paths:
        try:
            stat = os.stat(path)
            state.append((stat.st_mtime_ns, stat.st_size))
        except OSError:
            state.append(None)
    return state


async def watch_files(fronter):
    paths = fronter.watched_files()
    last = file_state(paths)

    while True:
        await asyncio.sleep(WATCH_INTERVAL)
        current = file_state(paths)
        if current != last:
            last = current
            fronter.reload("a file changed")


def make_socket(host, port, kind):
    family = family_of(host)
    sock = socket.socket(family, kind)

    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise

    return sock


async def main(args):
    if not os.path.exists(args.records):
        log.error("[!] Could not find %s", args.records)
        return

    if forwards_to_itself(args.upstream, args.bind, args.port):
        log.error("[!] Upstream %s points back at this server, change --upstream or --port", format_address(*args.upstream))
        return

    fronter = Fronter(args)
    fronter.reload()

    loop = asyncio.get_running_loop()
    transports = []
    servers = []
    watcher = None

    try:
        for host in args.bind:
            try:
                sock = make_socket(host, args.port, socket.SOCK_DGRAM)
                transport, _ = await loop.create_datagram_endpoint(lambda: UDPHandler(fronter), sock=sock)
                transports.append(transport)

                if not args.no_tcp:
                    sock = make_socket(host, args.port, socket.SOCK_STREAM)
                    server = await asyncio.start_server(lambda reader, writer: handle_tcp(fronter, reader, writer), sock=sock)
                    servers.append(server)
            except OSError as e:
                log.error("[!] Could not listen on %s: %s", format_address(host, args.port), e)
                return

            log.info("[+] DNS server listening on %s (%s)", format_address(host, args.port), "UDP" if args.no_tcp else "UDP and TCP")

        log.info("[+] Forwarding everything else to %s", format_address(*args.upstream))

        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(signal.SIGHUP, fronter.reload, "SIGHUP received")

        watcher = asyncio.create_task(watch_files(fronter))
        await asyncio.Event().wait()
    finally:
        if watcher:
            watcher.cancel()
        for transport in transports:
            transport.close()
        for server in servers:
            server.close()


def upstream_argument(text):
    try:
        return parse_address(text, UPSTREAM_PORT)
    except ValueError:
        raise argparse.ArgumentTypeError("\"{}\" is not an IP address with an optional port".format(text))


def bind_argument(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise argparse.ArgumentTypeError("\"{}\" is not an IP address".format(text))


def parse_args():
    parser = argparse.ArgumentParser(description="DNS proxy that answers some records itself and forwards everything else upstream")
    parser.add_argument("--upstream", type=upstream_argument, default=(UPSTREAM_SERVER, UPSTREAM_PORT), metavar="HOST[:PORT]",
                        help="upstream DNS server, use [ADDRESS]:PORT for IPv6 (default: {})".format(format_address(UPSTREAM_SERVER, UPSTREAM_PORT)))
    parser.add_argument("--bind", type=bind_argument, action="append", metavar="ADDRESS",
                        help="address to listen on, can be given more than once (default: {})".format(BIND_IP))
    parser.add_argument("--port", type=int, default=BIND_PORT, help="port to listen on (default: %(default)s)")
    parser.add_argument("--records", default=RECORDS_FILE, metavar="FILE", help="records file (default: records.txt next to this script)")
    parser.add_argument("--denylist", default=DENYLIST_FILE, metavar="FILE", help="clients to never answer (default: denylist.txt next to this script)")
    parser.add_argument("--allowlist", metavar="FILE", help="only answer clients listed in this file")
    parser.add_argument("--timeout", type=float, default=UPSTREAM_TIMEOUT, help="seconds to wait for the upstream server (default: %(default)s)")
    parser.add_argument("--no-tcp", action="store_true", help="only listen on UDP")

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_true", help="only log problems")
    verbosity.add_argument("--verbose", action="store_true", help="also log answers and upstream timings")

    args = parser.parse_args()

    if not 0 < args.port <= MAX_SHORT:
        parser.error("--port must be between 1 and {}".format(MAX_SHORT))
    if args.timeout <= 0:
        parser.error("--timeout must be more than 0")
    if not args.bind:
        args.bind = [BIND_IP]

    return args


if __name__ == '__main__':
    args = parse_args()

    logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    if args.quiet:
        log.setLevel(logging.WARNING)
    elif args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        log.info("[+] Shutting down")
