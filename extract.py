import pyshark,sys,binascii
from datetime import datetime
from nslookup import nslookup,QCLASS_MAP,QTYPE_MAP
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
        query_type = QTYPE_MAP[query_type]
        query_class = QCLASS_MAP[query_class]
        b += 4
        name = '.'.join(name)
        queries.append(name)
        l -= 1
    return [(q,query_type,query_class) for q in queries]

# file = "Pcaps/ PCAP_1_H1.pcap"
file = sys.argv[1]
csvfile = sys.argv[2]

# Open the capture and filter for port 53 traffic (DNS)
cap = pyshark.FileCapture(file,display_filter="udp.port == 53 || tcp.port == 53")
resolutions = []
for i,pkt in enumerate(cap):
    try:
        new_queries = process_pkt(pkt)
        for q in new_queries: 
            print("Extracted :\t",q)
            name,qtype,qclass = q
            # 100 queries in 1 minute is slightly more than 1 query in 0.5s
            sleep(0.5)
            a,n,d = nslookup(name,qtype,qclass)
            print("Number of RRs:",n)
            print("First Resolution:",a)
            print("Lookup Time:",d,'ms')
            resolutions.append(q+(a,n,d))
    except AttributeError:
        print("packet doesn't have IP addresses or ports.")
        continue

resolutions = pd.DataFrame(resolutions,columns=["query",'type','class','first_ans','num_ans_RR','lookup_time'])
resolutions.to_csv(csvfile,index=False)

## Analysis

print(100*resolutions['first_ans'].isnull().mean(),r"% of queries couldn't be answered")
print("Average lookup time is :",resolutions['lookup_time'].mean(),'ms')