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