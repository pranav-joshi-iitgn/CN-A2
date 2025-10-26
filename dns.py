import struct,random,sys,socket
from time import time,sleep
from datetime import datetime
from random import choices
ROOT_SERVER = '198.41.0.4'

# QTYPE_MAP = {
#     1: "A",
#     2: "NS",
#     3: "MD",
#     4: "MF",
#     5: "CNAME",
#     6: "SOA",
#     7: "MB",
#     8: "MG",
#     9: "MR",
#     10: "NULL",
#     11: "WKS",
#     12: "PTR",
#     13: "HINFO",
#     14: "MINFO",
#     15: "MX",
#     16: "TXT",
#     28: "AAAA",
#     33: "SRV",
#     41: "OPT",
#     252: "AXFR",
#     253: "MAILB",
#     254: "MAILA",
#     255: "ANY"
# }

# QTYPE_MAP_INV = {x:y for y,x in QTYPE_MAP.items()}

# QCLASS_MAP = {
#     1: "IN",    # Internet
#     2: "CS",    # CSNET (obsolete)
#     3: "CH",    # CHAOS
#     4: "HS",    # Hesiod
#     255: "ANY"
# }

# QCLASS_MAP_INV = {x:y for y,x in QCLASS_MAP.items()}

from maps import QTYPE_MAP,QTYPE_MAP_INV,QCLASS_MAP,QCLASS_MAP_INV

DNS_CACHE:dict[tuple,list] = {} # Exact match
NS_CACHE:dict[str,list] = {} # longest suffix match
CACHING = False
NS_CACHING = True
class ResourceRecord:
    def __init__(self,Name,Type,Class,TTL,RDlen,Value,logger=None):
        global CACHING,DNS_CACHE,NS_CACHE
        self.Name = Name
        if isinstance(Type,int):Type = QTYPE_MAP[Type]
        if isinstance(Class,int):Class = QCLASS_MAP[Class]
        self.Type = Type
        self.Class = Class
        self.TTL = TTL
        self.RDlen = RDlen
        self.Value = Value
        if CACHING:
            # if logger :
            #     logger.print("trying to push RR of type",self.Type,'into cache')
            if (Name,Type,Class) not in DNS_CACHE : 
                DNS_CACHE[(Name,Type,Class)] = S = set()
            else:
                S = DNS_CACHE[(Name,Type,Class)]
            S.add(self)
                # for RR in L :
                #     if RR.Value == Value: 
                #         RR.TTL = TTL
                #         break
                # else:L.append(self)

            # NS_CACHE
            if Type == 'NS' and NS_CACHING:
                if Name not in NS_CACHE:NS_CACHE[Name] = S = set()
                else:S = NS_CACHE[Name]
                S.add(self)
                    # for RR in L : 
                    #     if RR.Value == Value:
                    #         RR.TTL = TTL
                    #         break
                    # else:L.append(self)

    def __eq__(self,other):
        return (self.Name==other.Name) and (self.Class==other.Class) and (self.Type==other.Type) and (self.Value==other.Value)

    def __hash__(self):
        return hash((self.Name,self.Type,self.Class,self.Value))

    def __repr__(self):
        return f"({self.Name},{self.Type},{self.Class},{self.Value})"

def check_cache(Name,Type,Class):
    global DNS_CACHE
    if isinstance(Type,int):Type = QTYPE_MAP[Type]
    if isinstance(Class,int):Class = QCLASS_MAP[Class]
    key = (Name,Type,Class)
    if key not in DNS_CACHE : return []
    return list(DNS_CACHE[key])

# def check_ns_cache(Name,curr_zone=''):
#     global NS_CACHE
#     l = len(curr_zone)
#     if Name in NS_CACHE : zones = [Name] # exact match
#     else: 
#         zones = [x for x in NS_CACHE.keys() if (len(x) > l and Name.endswith('.'+x))]
#         if not zones : return None
#         zones = sorted(zones,key=lambda x:len(x),reverse=True)
#     for zone in zones:
#         servers = []
#         for RR in NS_CACHE[zone]: # NS record
#             servers.extend(check_cache(
#                 RR.Value, # The hostname of delegated server
#                 'A','IN'))
#         if servers:return zone,servers
#     return None

def check_ns_cache(Name,curr_zone=''):
    global NS_CACHE
    l = len(curr_zone)
    parts = Name.split('.')
    for num_parts in range(len(parts),l,-1):
        domain = parts[-num_parts:]
        domain = '.'.join(domain)
        if domain in NS_CACHE:
            assert isinstance(NS_CACHE,dict)
            RRs =NS_CACHE[domain]
            servers = []
            for RR in choices(list(RRs),k=5):
                servers.extend(check_cache(RR.Value,1,1))
            servers = list(set(servers))
            return domain,servers
    return None

def create_dns_query(name, qtype, qclass, RD=False, Cache=False):
    """
    Create a DNS query packet (byte array) for a given domain, qtype, and qclass.
    Additionaly, the RD flag can be set to do recursive resolution rather than iterative,
    and Cache flag can be set to only return authoritative RRs and not cached ones.
    Note that the Cache flag isn't actually used in real life. 
    But since I am running the queries one after another, without stopping the server, 
    I must do this for fair comparsion.
    """

    qtypes:list = qtype if isinstance(qtype,list) else [qtype]

    packet = bytearray()

    # Transaction ID: 16 bits, arbitrary value like 0x1234
    transaction_id = random.randint(0, 0xFFFF)
    packet += struct.pack('>H', transaction_id)

    # Flags: 16 bits
    flags = 0x0100 if RD else 0x0000
    flags = f"0000000{int(RD)}000{int(Cache)}0000"
    assert len(flags) == 16 , "wrong flags"
    flags = int(flags,2)
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
        'Z': (flags >> 4) & 0x7,        # Reserved, always zero, except when custom "Cache flag" is used
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

class Logger:
    def __init__(self,Enabled=True,LogFile=None,IndentLevel=0,TimeStamp=False,level=1):
        self.TS = TimeStamp
        self.E = Enabled
        self.l = IndentLevel
        self.file = LogFile
        self.level = level # The level of loging; 1 is most prioritised
    def print(self,*args,level=1, **kwargs):
        """Logs based on the parameters passed in constructor"""
        if self.level < level : return # If the log isn't important enough, skip
        if not self.E : return
        if not self.TS : print(self.l*"\t",*args,**kwargs,file=self.file)
        TS = str(datetime.now())
        print('[',TS,']',self.l*"\t",*args,**kwargs,file=self.file)

QUERIES_SENT = 0
ANSWERS_RECIEVED = 0

def send_dns_query(packet, server_ip=ROOT_SERVER, port=53, timeout=5,
    Log=False,LogFile=None,logger=None,measure_time=False):
    """Send the DNS query packet over UDP to the specified DNS server and return the response bytes."""
    global QUERIES_SENT,ANSWERS_RECIEVED
    if logger is not None: log = logger
    else: log = Logger(Log,LogFile,0,True)
    if measure_time:t0 = time()
    L3PROTO = socket.AF_INET6 if (":" in server_ip) else socket.AF_INET
    with socket.socket(L3PROTO, socket.SOCK_DGRAM) as sock:
        if timeout is not None : sock.settimeout(timeout)
        sock.sendto(packet, (server_ip, port))
        QUERIES_SENT += 1
        log.print('sent packet to',server_ip,'with timeout of',timeout,'s for response',level=3)
        response, _ = sock.recvfrom(512)  # DNS typically max UDP size 512 bytes
        # if Log: print('recieved packet from',server_ip,file=LogFile,flush=True)
        log.print('recieved packet from',server_ip,level=3)
        ANSWERS_RECIEVED += 1
    if measure_time: return response, float(time()-t0)
    return response


MAX_DEPTH =10

def ask(name,server=ROOT_SERVER,qtype=1,qclass=1,
    Log=False,RD=False,timeout=5,app_timeout=10,LogFile=None,depth=0,zone='',
    get_stats=False):
    global QUERIES_SENT, ANSWERS_RECIEVED
    QUERIES_SENT = 0
    ANSWERS_RECIEVED = 0
    if depth > MAX_DEPTH : raise RecursionError("Too much recursion")
    log = Logger(Log,LogFile,depth,True,2)
    parts_len = len(zone.split('.'))
    if not zone : server_type = '[ROOT]'
    elif parts_len == 1 : server_type = f'[{zone} TLD]'
    elif parts_len > 1 : server_type = f'[{zone} AUTH]'
    log.print(server_type,name,'@',server,'to be answered in',app_timeout,'s')
    if get_stats : 
        stats = {}
        stats['sum_RTT'] = 0
        stats['queries'] = 0
        stats['cache_hits'] = 0
        stats['cache_misses'] = 0
    t0 = time()
    def check_time(stage=0):
        elapsed_time = float(time()-t0)
        if elapsed_time > app_timeout: raise TimeoutError(f"Timeout error at stage {stage}")
    def get_remaining_time():
        remaining_time = app_timeout-float(time()-t0)
        return remaining_time

    if CACHING : 
        log.print('<0> Checking cache for direct hits',level=2)
        cached_records = check_cache(name,qtype,qclass)
        if cached_records : 
            log.print(f'[CACHE] HIT({name},{qtype},{qclass}) : Found',len(cached_records),'RRs')
            if get_stats:
                stats['cache_hits'] += 1
                return cached_records,stats
            return cached_records
        check_time(0)

        if name != zone and NS_CACHING:
            log.print('<1> Checking cache for NS records',level=2)
            try:ns_cached_records = check_ns_cache(name,zone)
            except Exception as e:
                log.print('chech_ns_cache had error ',e)
                raise e
        else:ns_cached_records = None

        if ns_cached_records:
            new_zone,RRs = ns_cached_records
            log.print('[CACHE] HIT : Found',len(RRs),'servers for zone',new_zone)
            if get_stats:stats['cache_hits'] += 1
            for RR in RRs:
                new_server = RR.Value
                log.print('Trying',RR.Name,'(',new_server,')',level=3)
                try:
                    answerRRs = ask(name,new_server,qtype,qclass,Log,RD,timeout,get_remaining_time(),LogFile,depth+1,new_zone,get_stats=get_stats)
                    if get_stats:
                        answerRRs,new_stats = answerRRs
                        update_stats(new_stats)
                    if not answerRRs:log.print(RR.Name,'did not return any answers',level=3)
                    else: 
                        if get_stats: return answerRRs,stats
                        return answerRRs
                except:
                    log.print('asking',RR.Name,'crashed',level=3)
                    break     
                check_time(1)       
        else: 
            log.print(f'[CACHE] MISS : {len(DNS_CACHE)} keys in cache and {len(NS_CACHE)} zones')
            if get_stats:stats['cache_misses'] += 1
        check_time(1)

    log.print('<2> Asking server for direct hits',level=2)
    pack = create_dns_query(name,qtype,qclass,RD)
    response = send_dns_query(pack,server,timeout=timeout,logger=log,measure_time=get_stats)
    if get_stats: 
        response, d = response
        log.print('* Response arrived from',server,'in',round(d*1000,2),'ms',level=2)
        stats['sum_RTT'] += d
        stats['queries'] += 1
    response = parse_dns_message(response)
    answerRRs = response['Answers']
    log.print("* Got",len(answerRRs),'Answer RRs',level=2)
    if answerRRs: 
        if get_stats: 
            log.print('[STAT] execution finished in :',round(1000*float(time()-t0),2),'ms')
            return answerRRs,stats
        return answerRRs 
    check_time(2)

    # If the desired thing was answered, awesome!
    # Otherwise, do NS stuff
    authorityRRs = response['Authority']
    additionalRRs = response['Additional']
    log.print('* Got',len(authorityRRs),'Authority RRs',level=2)
    log.print('* Got',len(additionalRRs),'Additional RRs',level=2)

    log.print("<3> Checking Additional RRs for delegated servers",level=2)
    def update_stats(new_stats):
        for x,y in new_stats.items(): 
            stats[x] += y

    NS_RRs = [RR for RR in authorityRRs if RR.Type=='NS' and len(RR.Name) > len(zone)]
    A_RRs = [RR for RR in additionalRRs if RR.Type=='A' or RR.Type=='AAAA']
    A_RR_IPs = [RR.Value for RR in A_RRs]
    for i,RR2 in enumerate(A_RRs):
        log.print(f'({i+1}) trying',RR2.Name,'(',RR2.Value,')',level=3)
        for j,RR in enumerate(NS_RRs):
            if RR.Value == RR2.Name: # found
                new_server = RR2.Value
                new_zone = RR.Name
                if zone.endswith(new_zone):continue
                try:
                    answerRRs =  ask(name,new_server,qtype,qclass,Log,RD,timeout,get_remaining_time(),LogFile,depth+1,new_zone,get_stats=get_stats)
                    if get_stats:
                        answerRRs,new_stats = answerRRs
                        update_stats(new_stats)
                    if not answerRRs:
                        log.print(RR2.Name,'did not return any answers',level=3)
                        break
                    else:
                        if get_stats :
                            log.print('[STAT] execution finished in :',round(1000*float(time()-t0),2),'ms')
                            return answerRRs,stats
                        return answerRRs
                except:
                    log.print('asking',RR2.Name,'crashed',level=3)
                    break
        else:log.print('\t',RR2.Name,'not matched with any NS Authority RR',level=3)
        check_time(3)
    log.print("<4> Trying to resolve values in Authority RRs to get IP address of delegated server",level=2)
    for i,RR in enumerate(NS_RRs[:5]):
        new_zone = RR.Name
        if zone.endswith(new_zone):continue
        log.print(f'({i+1}) getting',RR.Value,level=3)
        try:
            res = ask(RR.Value,ROOT_SERVER,1,1,Log,RD,timeout,get_remaining_time(),LogFile,depth+1,get_stats=get_stats)
            if get_stats:
                res,new_stats = res
                update_stats(new_stats)
        except:
            log.print('getting',RR.Value,'crashed',level=3)
            check_time(4)
            continue
        check_time(4)
        for j,new_server in enumerate(res[:5]):
            if new_server.Value in A_RR_IPs:continue
            log.print(f'({i+1}:{j+1}) trying',new_server.Value,level=3)
            try:
                res2 = ask(name,new_server.Value,qtype,qclass,Log,RD,timeout,get_remaining_time(),LogFile,depth+1,new_zone,get_stats=get_stats)
                if get_stats:
                    res2,new_stats = res2
                    update_stats(new_stats)
                if res2 : 
                    if get_stats: 
                        log.print('[STAT] execution finished in :',round(1000*float(time()-t0),2),'ms')
                        return res2, stats
                    return res2
                else:log.print(new_server.Value,"didn't return anything",level=3)
            except:log.print('asking',new_server.Value,'failed',level=3)
            check_time(4)
        log.print(RR.Value,"didn't work",level=3)
    if get_stats: 
        log.print('[STAT] gave up in :',round(1000*float(time()-t0),2),'ms')
        return [],stats
    return []

TOTAL_CACHE_HITS = 0
TOTAL_CACHE_MISSES = 0


def server(ip,Log=False,LogFile=None):
    global QUERIES_SENT,ANSWERS_RECIEVED,CACHING,TOTAL_CACHE_HITS,TOTAL_CACHE_MISSES
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 53))
    log = Logger(True,LogFile,0,True)
    log.print(f"[*] DNS server listening on {ip}:53")
    QUERIES_SENT = 0
    ANSWERS_RECIEVED = 0
    f = open('servers_stats.csv','w')
    def AddStatRow(*args):print(*args,sep=',',file=f,flush=True)
    AddStatRow('name','type','RD','Cache','sum_RTT','queries','total_time','cache_hits','cache_misses','num_answers')
    while True:
        try:
            data, addr = sock.recvfrom(512)
            log.print('* recieved from',addr,level=3)
            parsed = parse_dns_message(data)
            question = parsed['Questions'][0]
            qname = question['QName']
            qtype = question['QType']
            RD = parsed['RD']
            Cache = parsed['Z']
            log.print(f"[Query] {qname} (QTYPE={QTYPE_MAP[qtype]}) (RD={RD}) (Cache={Cache}) from {addr}")
            CACHING = bool(Cache) 
            t0 = time()
            answers,stats = ask(qname,ROOT_SERVER,qtype,1,Log,RD,LogFile=LogFile,get_stats=True)
            t1 = time()
            total_time = float(t1-t0)
            CACHING = True
            for x,y in stats.items(): log.print(x,':',y)
            sum_RTT = stats['sum_RTT']
            queries = stats['queries']
            log.print('[STAT] servers contacted :',queries)
            log.print('[STAT] average server communication time :',round(1000*sum_RTT/queries,2),'ms')
            log.print('[STAT] total server communication time :',round(1000*sum_RTT,2),'ms')
            log.print('[STAT] total time : ',round(1000*total_time,2),'ms')
            if Cache:
                cache_hits = stats['cache_hits']
                cache_misses = stats['cache_misses']
                log.print("[STAT] Cache hits :",cache_hits)
                log.print("[STAT] Cache misses :",cache_misses)
                TOTAL_CACHE_HITS += cache_hits
                TOTAL_CACHE_MISSES += cache_misses
                TOT = TOTAL_CACHE_HITS + TOTAL_CACHE_MISSES
                if TOT == 0 : hit_rate = 'NA'
                else: hit_rate = str(round(TOTAL_CACHE_HITS/TOT,2))+'%'
                log.print('[STAT] Updated hit rate :',hit_rate)
            else:
                cache_hits = ''
                cache_misses = ''
            AddStatRow(qname,qtype,RD,Cache,sum_RTT,queries,total_time,cache_hits,cache_misses,len(answers))
            if not answers:
                log.print("[!] No answers for",qname)
                response = (
                    data[:2] +  # Keep transaction ID
                    struct.pack('>H', 0x8183) +  # Flags: response, NXDOMAIN
                    data[4:12] +  # Keep question/answer counts from query
                    data[12:]  # Keep question section
                )
                sock.sendto(response, addr)
                continue

            # Build response header
            transaction_id = data[:2]
            flags = struct.pack('>H', 0x8180) # no error
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
                if rr.Type == 'A':rdata = bytes(map(int, rr.Value.split('.')))
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
            log.print(f"[Response] Sent {len(answers)} answers to {addr}")
            
        except KeyboardInterrupt:
            log.print("\n[!] Stopping server...")
            break
        except Exception as e:
            log.print("[Error]",e)
            # Send NXDOMAIN response
            response = (
                data[:2] +  # Keep transaction ID
                struct.pack('>H', 0x8183) + # Flags
                data[4:12] +  # Keep question/answer counts from query
                data[12:]  # Keep question section
            )
            sock.sendto(response, addr)
            CACHING = True

def client(name,server_ip,qtype=1,qclass=1,RD=False,Cache=False):
    pack = create_dns_query(name,qtype,qclass,RD,Cache)
    try:response = send_dns_query(pack,server_ip,timeout=None)
    except Exception as e:
        print(e)
        return []
    response = parse_dns_message(response)
    answers = response["Answers"]
    return answers

def custom_lookup(name,server_ip,qtype=1,qclass=1,RD=False,Cache=False):
    t0 = time()
    answers = client(name,server_ip,qtype,qclass,RD,Cache)
    t1 = time()
    d = int((t1-t0)*1000)
    n = len(answers)
    if n == 0 : a = None
    else: a = answers[0].Value
    return a,n,d

if __name__ == "__main__":
    Log = ("--log" in sys.argv)
    RD = ('--rd' in sys.argv)
    Cache = ('--c' in sys.argv)
    qtype = 1
    if "-a" in sys.argv:qtype = 1
    elif "-ns" in sys.argv:qtype = 2
    elif "-mx" in sys.argv:qtype = 15
    args = [x for x in sys.argv if not x.startswith('-')]
    if args[1] == "ask":
        name = args[2]
        CACHING = Cache
        answers =  ask(name,ROOT_SERVER,qtype,1,Log,RD,get_stats=True)
        for a in answers:print(a)
        if len(answers)==0: print('no answers')
    elif args[1] == "server":
        ip = args[2]
        if Log and (len(args) > 3):
            LogFile = args[3]
            with open(LogFile,'w') as LogFile:
                server(ip,True,LogFile)
        else: server(ip,False)
    elif args[1] == "client":
        name = args[2]
        server_ip = args[3]
        answers = client(name,server_ip,qtype,1,RD,Cache)
        print('Answers:')
        for a in answers:print('\t',a)
        
    else:print(f'invalid argument "{sys.argv[1]}"')
