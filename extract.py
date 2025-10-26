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
            row = (name,qtype,qclass)
            a,n,d = nslookup(name,qtype,qclass,nslookup_error_file)
            row += (a,n,d)
            print('[Default]')
            print("\tNumber of RRs:",n)
            print("\tFirst Resolution:",a)
            print("\tLookup Time:",d,'ms')
            # 100 queries in 1 minute is slightly more than 1 query in 0.5s
            sleep(0.5)
            a_c,n_c,d_c = custom_lookup(name,'10.0.0.5',qtype,qclass)
            row += (a_c,n_c,d_c)
            print('[Custom]')
            print("\tNumber of RRs:",n_c)
            print("\tFirst Resolution:",a_c)
            print("\tLookup Time:",d_c,'ms')
            sleep(1) # there are actually multiple queries done in one iterative resolution
            a_r,n_r,d_r = custom_lookup(name,'10.0.0.5',qtype,qclass,RD=True)
            row += (a_r,n_r,d_r)
            print('[Custom][RD]')
            print("\tNumber of RRs:",n_r)
            print("\tFirst Resolution:",a_r)
            print("\tLookup Time:",d_r,'ms')
            sleep(0.5)
            a_c,n_c,d_c = custom_lookup(name,'10.0.0.5',qtype,qclass,Cache=True)
            row += (a_c,n_c,d_c)
            print('[Custom][Cache]')
            print("\tNumber of RRs:",n_c)
            print("\tFirst Resolution:",a_c)
            print("\tLookup Time:",d_c,'ms')
            sleep(1) # there are actually multiple queries done in one iterative resolution
            resolutions.append(row)
    except AttributeError:
        print("packet doesn't have IP addresses or ports.")
        continue
nslookup_error_file.close()
resolutions = pd.DataFrame(
    resolutions,
    columns=(
        ["query",'type','class',
        'first_ans_default','num_ans_RR_default','lookup_time_default',
        'first_ans_custom','num_ans_RR_custom','lookup_time_custom',
        'first_ans_custom_RD','num_ans_RR_custom_RD','lookup_time_custom_RD',
        'first_ans_custom_Cache','num_ans_custom_Cache','lookup_time_custom_Cache']
        )
)
resolutions.to_csv(csvfile,index=False)