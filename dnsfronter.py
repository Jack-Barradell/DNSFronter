from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, CNAME, TXT, NS, PTR, MX
import socket
import asyncio

UPSTREAM_SERVER = "1.1.1.1"
BIND_IP = "0.0.0.0"
BIND_PORT = 53


async def forward_to_upstream(data):
    try:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        await loop.sock_sendall(sock, data)
        sock.connect((UPSTREAM_SERVER, 53))
        
        response = await asyncio.wait_for(
            loop.sock_recv(sock, 4096),
            timeout=5.0
        )
        sock.close()
        return response
    except Exception as e:
        print("[!] Error forwarding to upstream: {}".format(e))
        return None


async def handle_query(data, addr, sock, records, deny_list):
    client_ip = addr[0]
    
    try:
        if client_ip in deny_list:
            print("[-] Didn't answer request from {}".format(client_ip))
            return
        
        request = DNSRecord.parse(data)
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]
        
        print("[+] Query from {}: {} {}".format(client_ip, qname, qtype))
        
        found = False
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        
        for record in records:
            if record["name"] == qname and record["type"] == qtype:
                if record["type"] == "A":
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "AAAA":
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "CNAME":
                    reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "TXT":
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "NS":
                    reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "PTR":
                    reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(record["value"]), ttl=record["ttl"]))
                elif record["type"] == "MX":
                    reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(record["value"], record["priority"]), ttl=record["ttl"]))
                    
                found = True
                print("[+] Returning local record")
                sock.sendto(reply.pack(), addr)
        
        if not found:
            print("[+] Forwarding to upstream DNS server")
            upstream_response = await forward_to_upstream(data)
            if upstream_response:
                sock.sendto(upstream_response, addr)
        
        print("[+] Response sent")
    
    except Exception as e:
        print("[!] Encountered exception: {}".format(e))


async def main():
    lines = []
    records = []
    deny_list = []
    
    with open("records.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            lines.append(line)
    
    did_load = 0
    didnt_load = 0
    
    for line in lines:
        split = line.split(" ")
        if len(split) < 4:
            print("[!] Could not load record \"{}\" as it does not meet the expected format".format(line))
            didnt_load += 1
            continue
        
        if split[0] not in ["A", "AAAA", "CNAME", "TXT", "NS", "PTR", "MX"]:
            print("[!] Could not load record \"{}\" as record type \"{}\" is not one of A, AAAA, CNAME, TXT, NS, PTR, MX".format(line, split[0]))
            didnt_load += 1
            continue
        
        if not split[3].isdigit():
            print("[!] Could not load record \"{}\" as TTL is not a valid positive integer".format(line))
            didnt_load += 1
            continue
        
        new_record = {
            "type": split[0],
            "name": split[1].lower(),
            "value": split[2].replace("\s", " "),
            "ttl": int(split[3]),
        }
        
        if split[0] == "MX":
            if len(split) >= 5 and split[4].isdigit():
                new_record["priority"] = int(split[4])
            else:
                new_record["priority"] = 10
        
        records.append(new_record)
        did_load += 1
    
    print("[+] Loaded {} records".format(did_load))

    if didnt_load > 0:
        print("[-] Didn't load {} records".format(didnt_load))
    
    with open("denylist.txt", "r") as f:
        for line in f:
            deny_list.append(line.strip())

    
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((BIND_IP, BIND_PORT))
    server.setblocking(False)
    
    print("[+] DNS server listening on {}:{}".format(BIND_IP, BIND_PORT))
    
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            data, addr = await loop.sock_recvfrom(server, 4096)

            asyncio.create_task(handle_query(data, addr, server, records, deny_list))
        
        except Exception as e:
            print("[!] Encountered exception: {}".format(e))


if __name__ == '__main__':
    asyncio.run(main())