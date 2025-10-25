import struct,random,sys,socket
from time import time,sleep
ROOT_SERVER = '198.41.0.4'

QTYPE_MAP = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "ANY"
}

QTYPE_MAP_INV = {x:y for y,x in QTYPE_MAP.items()}

QCLASS_MAP = {
    1: "IN",    # Internet
    2: "CS",    # CSNET (obsolete)
    3: "CH",    # CHAOS
    4: "HS",    # Hesiod
    255: "ANY"
}

QCLASS_MAP_INV = {x:y for y,x in QCLASS_MAP.items()}

class ResourceRecord:
    def __init__(self,Name,Type,Class,TTL,RDlen,Value):
        self.Name = Name
        self.Type = Type if isinstance(Type,str) else QTYPE_MAP[Type]
        self.Class = Class if isinstance(Class,str) else QCLASS_MAP[Class]
        self.TTL = TTL
        self.RDlen = RDlen
        self.Value = Value

    def __repr__(self):
        return f"({self.Name},{self.Type},{self.Class},{self.Value})"

def create_dns_query(name, qtype, qclass, RD=False):
    """Create a DNS query packet (byte array) for a given domain, qtype, and qclass."""

    qtypes:list = qtype if isinstance(qtype,list) else [qtype]

    packet = bytearray()

    # Transaction ID: 16 bits, arbitrary value like 0x1234
    transaction_id = random.randint(0, 0xFFFF)
    packet += struct.pack('>H', transaction_id)

    # Flags: 16 bits
    flags = 0x0100 if RD else 0x0000
    packet += struct.pack('>H', flags)

    # Questions: 16 bits, set to 1
    packet += struct.pack('>H', len(qtypes))

    # Answer RRs, Authority RRs, Additional RRs: all 0
    packet += struct.pack('>H', 0)  # Answer RRs
    packet += struct.pack('>H', 0)  # Authority RRs
    packet += struct.pack('>H', 0)  # Additional RRs


    # Question section: 
    for qtype in qtypes:
        # convert domain name into DNS format
        for part in name.split('.'):
            packet.append(len(part))
            packet.extend(part.encode())
        packet.append(0)  # Terminate with zero length byte

        # QTYPE (16 bits)
        packet += struct.pack('>H', qtype)

        # QCLASS (16 bits)
        packet += struct.pack('>H', qclass)

    return bytes(packet)

QUERIES_SENT = 0
ANSWERS_RECIEVED = 0

def send_dns_query(packet, server_ip=ROOT_SERVER, port=53, timeout=5,Log=False,LogFile=None):
    """Send the DNS query packet over UDP to the specified DNS server and return the response bytes."""
    global QUERIES_SENT,ANSWERS_RECIEVED
    L3PROTO = socket.AF_INET6 if (":" in server_ip) else socket.AF_INET
    with socket.socket(L3PROTO, socket.SOCK_DGRAM) as sock:
        if timeout is not None : sock.settimeout(timeout)
        sock.sendto(packet, (server_ip, port))
        QUERIES_SENT += 1
        if Log: print('sent packet to',server_ip,file=LogFile,flush=True)
        if Log: print('timeout :',timeout,file=LogFile,flush=True)
        response, _ = sock.recvfrom(512)  # DNS typically max UDP size 512 bytes
        if Log: print('recieved packet from',server_ip,file=LogFile,flush=True)
        ANSWERS_RECIEVED += 1
    return response

def parse_dns_name(data, offset):
    """Parse a DNS encoded domain name (with possible pointers) starting at offset."""
    labels = []
    initial_offset = offset
    jumped = False

    while True:
        length = data[offset]

        # Pointer indicated by 11 for first 2 bits [RFC 1035]
        if length & 0xC0 == 0xC0:
            if not jumped:
                initial_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue

        # Zero length means end of name
        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(data[offset:offset + length].decode())
        offset += length

    if not jumped:return '.'.join(labels), offset
    else:return '.'.join(labels), initial_offset

def parse_dns_flags(flags):
    """Decode individual DNS header flags."""
    return {
        'QR': (flags >> 15) & 1,       # Query (0) / Response (1)
        'Opcode': (flags >> 11) & 0xF,  # Operation code
        'AA': (flags >> 10) & 1,        # Authoritative Answer
        'TC': (flags >> 9) & 1,         # Truncated
        'RD': (flags >> 8) & 1,         # Recursion Desired
        'RA': (flags >> 7) & 1,         # Recursion Available
        'Z': (flags >> 4) & 0x7,        # Reserved, always zero
        'RCODE': flags & 0xF            # Response code
    }

# Helper function to parse resource records
def parse_rr(data, offset):
    name, offset = parse_dns_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlength]
    offset += rdlength
    # Decode RDATA by type
    if rtype == 1 and rdlength == 4:  # A record (IPv4)
        rdata = '.'.join(str(b) for b in rdata)
    elif rtype == 28 and rdlength == 16:  # AAAA record (IPv6)
        # Convert 16 bytes to standard IPv6 notation
        parts = [f'{(rdata[i] << 8) | rdata[i + 1]:x}' for i in range(0, 16, 2)]
        ipv6 = ':'.join(parts)
        # Optional: compress consecutive zeros (human-readable)
        while ':::' in ipv6:ipv6 = ipv6.replace(':::', '::')
        rdata = ipv6
    elif rtype == 5 or rtype == 2:  # CNAME or NS
        rdata, _ = parse_dns_name(data, offset - rdlength)
    else:rdata = rdata.hex()
    return ResourceRecord(name,rtype,rclass,ttl,rdlength,rdata),offset


def parse_dns_message(data):
    """Parse a full DNS message and return its components as a dictionary."""
    result = {}

    # Header
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
    result['TransactionID'] = transaction_id
    result['Flags'] = format(flags, '016b')
    result['QR'] = (flags >> 15) & 1        # Query (0) / Response (1)
    result['Opcode'] = (flags >> 11) & 0xF   # Operation code
    result['AA'] = (flags >> 10) & 1         # Authoritative Answer
    result['TC'] = (flags >> 9) & 1          # Truncated
    result['RD'] = (flags >> 8) & 1          # Recursion Desired
    result['RA'] = (flags >> 7) & 1          # Recursion Available
    result['Z'] = (flags >> 4) & 0x7         # Reserved, always zero
    result['RCODE'] = flags & 0xF            # Response code
    result['QuestionCount'] = qdcount
    result['AnswerCount'] = ancount
    result['AuthorityCount'] = nscount
    result['AdditionalCount'] = arcount

    offset = 12

    # Questions
    questions = []
    for _ in range(qdcount):
        qname, offset = parse_dns_name(data, offset)
        qtype, qclass = struct.unpack('>HH', data[offset:offset + 4])
        offset += 4
        questions.append({'QName': qname, 'QType': qtype, 'QClass': qclass})
    result['Questions'] = questions


    # Answers
    answers = []
    for _ in range(ancount):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)
    result['Answers'] = answers

    # Authority RRs
    authority = []
    for _ in range(nscount):
        rr, offset = parse_rr(data, offset)
        authority.append(rr)
    result['Authority'] = authority

    # Additional RRs
    additional = []
    for _ in range(arcount):
        rr, offset = parse_rr(data, offset)
        additional.append(rr)
    result['Additional'] = additional

    return result

MAX_DEPTH =10

def ask(name,server=ROOT_SERVER,qtype=1,qclass=1,Log=False,RD=False,timeout=5,app_timeout=10,LogFile=None,depth=0):
    if depth > MAX_DEPTH : raise RecursionError("Too much recursion")
    if Log : print('\t'*depth,name,'@',server,'to be answered in',app_timeout,'s',file=LogFile,flush=True)
    t0 = time()
    pack = create_dns_query(name,qtype,qclass,RD)
    response = send_dns_query(pack,server,timeout=timeout,Log=Log,LogFile=LogFile)
    def check_time(stage=0):
        elapsed_time = float(time()-t0)
        if Log : print('\t'*depth,'elapsed time:',elapsed_time,'s',file=LogFile,flush=True)
        if elapsed_time > app_timeout: raise TimeoutError(f"stage {stage}")
    def get_remaining_time():
        remaining_time = app_timeout-float(time()-t0)
        if Log : print('\t'*depth,'remaining_time:',remaining_time,'s',file=LogFile,flush=True)
        return remaining_time
    check_time(1)
    response = parse_dns_message(response)
    answerRRs = response['Answers']
    if Log : print('\t'*depth,name,'@',server,":",len(answerRRs),'RRs',file=LogFile,flush=True)
    if answerRRs: return answerRRs 
    check_time(2)
    authorityRRs = response['Authority']
    additionalRRs = response['Additional']
    if Log : print('\t'*depth,name,'#',server,":",len(authorityRRs),'RRs',file=LogFile,flush=True)
    if Log : print('\t'*depth,name,'$',server,":",len(additionalRRs),'RRs',file=LogFile,flush=True)

    # If the desired thing was answered, awesome!
    # Otherwise, do NS stuff
    pack = create_dns_query(name,2,1)
    response = send_dns_query(pack,server,timeout=timeout,Log=Log,LogFile=LogFile)
    check_time(3)
    response = parse_dns_message(response)
    NS_RRs = [RR for RR in authorityRRs if RR.Type=='NS']
    A_RRs = [RR for RR in additionalRRs if RR.Type=='A' or RR.Type=='AAAA']
    if Log: print('\t'*depth,"Moving to stage 4",file=LogFile,flush=True)
    for i,RR2 in enumerate(A_RRs):
        if Log: print("\t"*depth,'trying',i+1,':',RR2.Value,file=LogFile,flush=True)
        for j,RR in enumerate(NS_RRs):
            if RR.Value == RR2.Name: # found
                new_server = RR2.Value
                try:return ask(name,new_server,qtype,qclass,Log,RD,timeout,get_remaining_time(),LogFile,depth+1)
                except:break
        else:
            if Log : print("\t"*depth,RR2.Value,'not matched',file=LogFile,flush=True)
        check_time(4)
    if Log: print('\t'*depth,"Moving to stage 5",file=LogFile,flush=True)
    for RR in NS_RRs[:5]:
        res = ask(RR.Value,ROOT_SERVER,1,1,Log,RD,timeout,get_remaining_time(),LogFile,depth+1)
        check_time(5)
        for new_server in res[:5]:
            try:
                res2 = ask(name,new_server.Value,qtype,qclass,Log,RD,timeout,get_remaining_time(),LogFile,depth+1)
                if res2 : return res2
            except:pass
            check_time(6)
    return []

def server(ip,Log=False,RD=False,LogFile=None):
    global QUERIES_SENT,ANSWERS_RECIEVED
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 53))
    print(f"[*] DNS server listening on {ip}:53",file=LogFile,flush=True)
    QUERIES_SENT = 0
    ANSWERS_RECIEVED = 0
    while True:
        try:
            data, addr = sock.recvfrom(512)
            print('recieved from',addr,file=LogFile,flush=True)
            
            parsed = parse_dns_message(data)
            question = parsed['Questions'][0]
            qname = question['QName']
            qtype = question['QType']
            
            print(f"[Query] {qname} (type={qtype}) from {addr}",file=LogFile,flush=True)
            
            answers = ask(qname,ROOT_SERVER,qtype,1,Log,RD,LogFile=LogFile)
            
            if Log: print('Queries Sent :',QUERIES_SENT,file=LogFile,flush=True)
            if Log: print('Answers Recieved :',ANSWERS_RECIEVED,file=LogFile,flush=True)

            if not answers:
                print(f"[!] No answers for {qname}",file=LogFile,flush=True)
                # Send NXDOMAIN response
                response = (
                    data[:2] +  # Keep transaction ID
                    struct.pack('>H', 0x8183) +  # Flags: response, NXDOMAIN
                    data[4:12] +  # Keep question/answer counts from query
                    data[12:]  # Keep question section
                )
                sock.sendto(response, addr)
                continue
            
            print(answers,file=LogFile,flush=True)

            # Build response header
            transaction_id = data[:2]
            flags = struct.pack('>H', 0x8180)  # Response, no error
            qdcount = struct.pack('>H', 1)
            ancount = struct.pack('>H', len(answers))
            nscount = struct.pack('>H', 0)
            arcount = struct.pack('>H', 0)
            
            # Copy question section from query
            question_section = data[12:]
            
            # Build answer section
            answer_section = b''
            for rr in answers:
                # Pointer to question name
                answer_section += struct.pack('>H', 0xC00C)
                
                # Type and Class
                rtype = QTYPE_MAP_INV[rr.Type]
                rclass = QCLASS_MAP_INV[rr.Class]
                answer_section += struct.pack('>HHI', rtype, rclass, rr.TTL)
                
                # RDATA
                if rr.Type == 'A':
                    rdata = bytes(map(int, rr.Value.split('.')))
                elif rr.Type == 'AAAA':
                    parts = [int(x, 16) for x in rr.Value.split(':')]
                    rdata = b''.join(struct.pack('>H', p) for p in parts)
                else:
                    # For NS, CNAME, etc., encode the domain name
                    rdata = b''
                    for part in rr.Value.split('.'):
                        rdata += bytes([len(part)]) + part.encode()
                    rdata += b'\x00'
                
                answer_section += struct.pack('>H', len(rdata)) + rdata
            
            # Assemble complete response
            response = transaction_id + flags + qdcount + ancount + nscount + arcount + question_section + answer_section
            sock.sendto(response, addr)
            print(f"[Response] Sent {len(answers)} answers to {addr}",file=LogFile,flush=True)
            
        except KeyboardInterrupt:
            print("\n[!] Stopping server...",file=LogFile,flush=True)
            break
        except Exception as e:
            print(f"[Error] {e}",file=LogFile,flush=True)
            # Send NXDOMAIN response
            response = (
                data[:2] +  # Keep transaction ID
                struct.pack('>H', 0x8183) +  # Flags: response, NXDOMAIN
                data[4:12] +  # Keep question/answer counts from query
                data[12:]  # Keep question section
            )
            sock.sendto(response, addr)

def client(name,server_ip,qtype=1,qclass=1,RD=False):
    pack = create_dns_query(name,qtype,qclass,RD)
    try:response = send_dns_query(pack,server_ip,timeout=None)
    except Exception as e:
        print(e)
        return []
    response = parse_dns_message(response)
    flags = response['Flags']
    answers = response["Answers"]
    if flags != "1000000110000000":print(f'{name}@{server_ip} response flags:',flags)
    return answers

def custom_lookup(name,server_ip,qtype=1,qclass=1,RD=False):
    t0 = time()
    answers = client(name,server_ip,qtype,qclass,RD)
    t1 = time()
    d = int((t1-t0)*1000)
    n = len(answers)
    if n == 0 : a = None
    else: a = answers[0].Value
    return a,n,d

if __name__ == "__main__":
    Log = ("--log" in sys.argv)
    RD = ('--rd' in sys.argv)
    qtype = 1
    if "-a" in sys.argv:qtype = 1
    elif "-ns" in sys.argv:qtype = 2
    elif "-mx" in sys.argv:qtype = 15
    args = [x for x in sys.argv if not x.startswith('-')]
    if args[1] == "ask":
        name = args[2]
        answers =  ask(name,ROOT_SERVER,qtype,1,Log,RD)
        for a in answers:print(a)
        if len(answers)==0: print('no answers')
    elif args[1] == "server":
        ip = args[2]
        if Log and (len(args) > 3):
            LogFile = args[3]
            with open(LogFile,'w') as LogFile:
                server(ip,True,RD,LogFile)
        else: server(ip,False,RD)
    elif args[1] == "client":
        name = args[2]
        server_ip = args[3]
        answers = client(name,server_ip,qtype,1,RD)
        print('Answers:')
        for a in answers:print('\t',a)
        
    else:print(f'invalid argument "{sys.argv[1]}"')
