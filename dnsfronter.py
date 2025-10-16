from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, CNAME, TXT, NS, PTR, MX
import socket

UPSTREAM_SERVER = "1.1.1.1"
BIND_IP = "0.0.0.0"
BIND_PORT = 53

def main():
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
            "name": split[1],
            "value": split[2],
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
    
    print("[+] DNS server listening on {}:{}".format(BIND_IP, BIND_PORT))
    
    while True:
        try:
            data, addr = server.recvfrom(4096)
            client_ip = addr[0]
            
            if client_ip in deny_list:
                print("[-] Didn't answer request from {}".format(client_ip))
                continue
            
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
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
                    server.sendto(reply.pack(), addr)
            
            if not found:
                print("[+] Forwarding to upstream DNS server")
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                upstream_sock.settimeout(5)
                upstream_sock.sendto(data, (UPSTREAM_SERVER, 53))
                upstream_response, _ = upstream_sock.recvfrom(4096)
                upstream_sock.close()
                server.sendto(upstream_response, addr)
            
            print("[+] Response sent")
        
        except Exception as e:
            print("[!] Encountered exception: {}".format(e))


if __name__ == '__main__':
    main()
