import subprocess
from time import time

# DNS QTYPE and QCLASS mappings (from RFC 1035 and later updates)
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

QCLASS_MAP = {
    1: "IN",    # Internet
    2: "CS",    # CSNET (obsolete)
    3: "CH",    # CHAOS
    4: "HS",    # Hesiod
    255: "ANY"
}

def nslookup(name, qtype=1, qclass=1,nslookup_error_file=None):
    """Perform an nslookup with specified QTYPE and QCLASS numbers."""

    # Look up symbolic values
    if isinstance(qtype,int):qtype = QTYPE_MAP.get(qtype, "A")
    if isinstance(qclass,int):qclass = QCLASS_MAP.get(qclass, "IN")
    
    # start timer
    t0 = time()

    # Run nslookup with query type and class
    process = subprocess.Popen(
        ["nslookup", "-querytype=" + qtype, "-class=" + qclass, name],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True
    )
    stdout, stderr = process.communicate()


    print(stdout,file=nslookup_error_file,flush=True)
    print(stderr,file=nslookup_error_file,flush=True)

    if 'error' in stdout: print('some issue in nslookup. Check log')

    # end time and kill process
    t1 = time()
    process.kill()

    # compute look-up time
    lookup_time = int((t1-t0)*1000) # ms

    # Extract IP addresses from output
    lines = stdout.split('\n')
    addresses = [line.replace("Address: ", '') for line in lines if line.startswith("Address: ")]
    
    #prepare response
    num_RR = len(addresses)
    if num_RR:first_address = addresses[0]
    else:first_address = None
    return first_address, num_RR, lookup_time

# Example usage
if __name__ == "__main__":
    print(nslookup("www.google.com", qtype='A', qclass='IN'))
    print(nslookup('buynowfromusa.com'))
