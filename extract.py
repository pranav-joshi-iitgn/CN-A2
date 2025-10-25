import pyshark,sys,binascii
from datetime import datetime
from nslookup import nslookup,QCLASS_MAP,QTYPE_MAP
from dns import custom_lookup
import pandas as pd
from time import sleep

def process_pkt(pkt) -> list:
    global messages
    src = pkt.ip.src # source IP address
    dst = pkt.ip.dst # destination IP address
    proto = pkt.transport_layer # transport layer protocol
    # For UDP/TCP packets, the application data is in the "udp.payload" or "tcp.payload"
    if proto == "UDP":payload = pkt.udp.payload
    elif proto == "TCP":payload = pkt.tcp.payload
    else:payload = ""
    # The time (with date) when the packet was sniffed/received
    try :
        t = pkt.sniff_time 
        assert t
    except: t = "-"*10
    # showing information about the extracted packet
    if payload:print(f"{t}\t : {proto} {src} → {dst} : {payload[:10]}...")
    else:print(f"{t}\t : {proto} {src} → {dst} : no payload")
    # get the length (bytes 4,5 (0 index))
    B = payload.split(':')
    l = B[4] + B[5]
    l = int(l,16)
    b = 12 # byte number
    queries = []
    while l > 0 :
        name = []
        while True:
            part_len = int(B[b],16) # bytes for this part
            b += 1
            if part_len == 0 : break # null character
            part = (''.join(B[b:b + part_len]))
            part = binascii.unhexlify(part).decode()
            name.append(part)
            b += part_len
        query_type = int(B[b] + B[b+1],16)
        query_class = int(B[b+2] + B[b+3],16)
        # query_type = QTYPE_MAP[query_type]
        # query_class = QCLASS_MAP[query_class]
        b += 4
        name = '.'.join(name)
        queries.append(name)
        l -= 1
    return [(q,query_type,query_class) for q in queries]

only_iter = ('--only_iter' in sys.argv)
args = [x for x in sys.argv if not x.startswith('-')]

# file = "Pcaps/ PCAP_1_H1.pcap"
file = args[1]
csvfile = args[2]

# Open the capture and filter for port 53 traffic (DNS)
cap = pyshark.FileCapture(file,display_filter="udp.port == 53 || tcp.port == 53")
resolutions = []
nslookup_error_file = open('nslookup_log.txt','w')
for i,pkt in enumerate(cap):
    print('[Packet',i+1,']')
    try:
        new_queries = process_pkt(pkt)
        for q in new_queries: 
            print("Extracted :\t",q)
            name,qtype,qclass = q
            a,n,d = nslookup(name,qtype,qclass,nslookup_error_file)
            print("\tNumber of RRs:",n)
            print("\tFirst Resolution:",a)
            print("\tLookup Time:",d,'ms')
            # 100 queries in 1 minute is slightly more than 1 query in 0.5s
            sleep(0.5)
            a_c,n_c,d_c = custom_lookup(name,'10.0.0.5',qtype,qclass)
            print("\t(custom) Number of RRs:",n_c)
            print("\t(custom) First Resolution:",a_c)
            print("\t(custom) Lookup Time:",d_c,'ms')
            sleep(1) # there are actually multiple queries done in one iterative resolution
            if not only_iter:
                a_r,n_r,d_r = custom_lookup(name,'10.0.0.5',qtype,qclass,RD=True)
                print("\t(custom) (RD) Number of RRs:",n_r)
                print("\t(custom) (RD) First Resolution:",a_r)
                print("\t(custom) (RD) Lookup Time:",d_r,'ms')
                resolutions.append(q+(a,n,d,a_c,n_c,d_c,a_r,n_r,d_r))
            else: resolutions.append(q+(a,n,d,a_c,n_c,d_c))
            sleep(0.5)
    except AttributeError:
        print("packet doesn't have IP addresses or ports.")
        continue
nslookup_error_file.close()
resolutions = pd.DataFrame(
    resolutions,
    columns=(
        ["query",'type','class',
        'first_ans_default','num_ans_RR_default','lookup_time_default',
        'first_ans_custom','num_ans_RR_custom','lookup_time_custom'
        ] + ([] if only_iter else ['first_ans_custom_RD','num_ans_RR_custom_RD','lookup_time_custom_RD'])
        )
)
resolutions.to_csv(csvfile,index=False)