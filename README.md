# Computer Networks (CS 331) Assignment 2

DISCLAIMER : Some scripts (mainly `config.sh` and `listener_setup.sh`) change global configuration in system, such as `/etc/resolv.conf` and affect connetivity to internet. 

## Part A

![topology](topo.svg)

This mininet topology is created using the MiniNet Python API in the file `topo.py`. You can access it as :

```bash
sudo python3 topo.py --only_topo
```

Note that the `--only_topo` is necessary since I am using `topo.py` without arguments for part D.

The command might return a lot of warnings, namely about addling links with too high bandwidth. This is because of the linux kernel's initial settings which the MiniNet hosts inherit. These warnings are harmless.

Just before the prompt, you will see something like this :

```
*** Ping: testing ping reachability
dns -> h1 h2 h3 h4 
h1 -> dns h2 h3 h4 
h2 -> dns h1 h3 h4 
h3 -> dns h1 h2 h4 
h4 -> dns h1 h2 h3 
*** Results: 0% dropped (20/20 received)
*** Starting CLI:
mininet> 
```

This is the output of the `pingAll()` method that was executed from the python script before starting the CLI using `CLI(net)`.

You can recreate this by issuing the `pingall` command in the CLI.

```
*** Starting CLI:
mininet> pingall
*** Ping: testing ping reachability
dns -> h1 h2 h3 h4 
h1 -> dns h2 h3 h4 
h2 -> dns h1 h3 h4 
h3 -> dns h1 h2 h4 
h4 -> dns h1 h2 h3 
*** Results: 0% dropped (20/20 received)
mininet> 
```

This demonstrated connectivity between the hosts.

But for sake of completeness, you can also ping hosts indivisually as

```
mininet> h1 ping h2
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=18.8 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=18.2 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=18.1 ms
64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=18.1 ms
^C
--- 10.0.0.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3002ms
rtt min/avg/max/mdev = 18.129/18.317/18.849/0.306 ms
mininet> h1 ping 10.0.0.2
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=19.2 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=18.2 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=18.1 ms
^C
--- 10.0.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 18.137/18.518/19.174/0.465 ms
mininet> 
```

## Part B

The default host resolver for linux systems is the stub resolver bound to IP address `127.0.0.53` (or `127.0.0.54`) and port `53` (DNS). This stub-resolver is part of `systemd-resolved` . 

Whenever a process needs do to DNS resolution, it looks at a configuration file, such as `/etc/resolv.conf` (this is actually a sym-link) which has IP addresses for name-servers (local resolver server processes or actual DNs servers) that it goes through in the given order and tries to resolve its query.

```
nameserver 127.0.0.53
options edns0 trust-ad
search .
```

For example, adding `nameserver 8.8.8.8` (Google's public recursive DNS resolver) on before the stub resolver will give `8.8.8.8` more priority.

What we want is for the Mininet hosts to be able to use the machine's stub resolver. They will not be able to do that directly because the subnet that their IP addresses belong to is incompatible (unable to talk) with `127.0.0.53` and because their IP addresses only make sense in the MiniNet namespace; not in the real internet (no machine, including the local machine knows how to forward packets to a `10.0.0.x` address Mininet host process/thread). To make it valid, we must either introduce the MiniNet hosts to the internet (at least the laptop) via DHCP, or use Name Address Translation (NAT). I chose the second option.

To add a node that does the translation and communicates with the outside world, we can do `net.addNAT(name='n0').configDefault()` . To run `topo.py` with NAT, use this command :

```bash
sudo python3 topo.py --only_nat 
```

Adding a node with the sole purpose of NAT will change the topology slightly to this:

```
mininet> net
dns dns-eth0:s2-eth2
h1 h1-eth0:s1-eth1
h2 h2-eth0:s2-eth1
h3 h3-eth0:s3-eth1
h4 h4-eth0:s4-eth1
n0 n0-eth0:s1-eth3
s1 lo:  s1-eth1:h1-eth0 s1-eth2:s2-eth3 s1-eth3:n0-eth0
s2 lo:  s2-eth1:h2-eth0 s2-eth2:dns-eth0 s2-eth3:s1-eth2 s2-eth4:s3-eth2
s3 lo:  s3-eth1:h3-eth0 s3-eth2:s2-eth4 s3-eth3:s4-eth2
s4 lo:  s4-eth1:h4-eth0 s4-eth2:s3-eth3
c0
```

Note that the node `n0` is the NAT device and `c0` is the controller for the switches.

Now, we will be able to PING IP addresses that are not in the subnet that the topology sits in.

```
mininet> h1 ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=114 time=24.4 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=114 time=17.2 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=114 time=16.0 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=114 time=15.9 ms
^C
--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 15.885/18.384/24.361/3.490 ms
```

Note that `n0` still has an IP address in the `10.x.x.x` subnet. This can be verified by its `ifconfig`

```
n0-eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.6  netmask 255.0.0.0  broadcast 10.255.255.255
        inet6 fe80::ece0:2cff:fe68:6ae3  prefixlen 64  scopeid 0x20<link>
        ether ee:e0:2c:68:6a:e3  txqueuelen 1000  (Ethernet)
        RX packets 154  bytes 20808 (20.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 66  bytes 7966 (7.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Thus, although the Mininet hosts can now talk to the internet, they still can't use the stub resolver since it isn't in the Mininet namespace.

To allow them to use the stub resolver, we must add a listener for requests to the stub resolver on another IP address (`10.0.0.6`). We do this as :

```
sudo mkdir /etc/systemd/resolved.conf.d/
sudo echo "DNSStubListenerExtra=10.0.0.6" > /etc/systemd/resolved.conf.d/additional-listening-interfaces.conf
```

If you already have the file `/etc/systemd/resolved.conf.d/additional-listening-interfaces.conf` , you can do :

```
sudo echo "DNSStubListenerExtra=10.0.0.6" >> /etc/systemd/resolved.conf.d/additional-listening-interfaces.conf
```

Now, after this, we also need to change the `/etc/resolv.conf` file so that the MiniNet hosts will try the `10.0.0.6` address as the IP address for a DNS server.

We can do this easily using `sudo sh config.sh`. The `config.sh` file adds `nameserver 10.0.0.6` to the top of `/etc/resolv.conf` only if it is not there.

Similarly, you have `unconfig.sh` which removes the line `nameserver 10.0.0.6` .

After doing this, we can do `nslookup` from inside the MiniNet CLI.

```
mininet> h1 sh config.sh
Adding 'nameserver 10.0.0.6' to the top of /etc/resolv.conf...
Done.
mininet> h1 nslookup google.com
Server:         10.0.0.6
Address:        10.0.0.6#53

Non-authoritative answer:
Name:   google.com
Address: 142.250.192.78
Name:   google.com
Address: 2404:6800:4009:829::200e
```

Now, by timing the `nslookup` command, we can get measured values for lookup latency for different DNS queries extracted from the PCAP files. 
Since there are a lot of queries (around 100 per file), it is better to script it.

The `nslookup.py` module is a wrapper around the `nlookup` linux command that measures the latency as well. 

Using that, the script `extract.py` get the latency values for DNS queries found in the PCAP files.

This data, along with data from the custom resolver for part C and D is then written to CSV files, such as `H1.csv`, based on the PCAP file and the Mininet host that ran the command.

The data we are interested in looks like this

| query                       | type | class | first_ans_default | num_ans_RR_default | lookup_time_default |
| --------------------------- | ---- | ----- | ----------------- | ------------------ | ------------------- |
| tuhafhaberler.com           | 1    | 1     |                   | 0                  | 57                  |
| rtsab.com                   | 1    | 1     |                   | 0                  | 442                 |
| i-butterfly.ru              | 1    | 1     | 104.21.88.172     | 2                  | 357                 |
| datepanchang.com            | 1    | 1     | 13.75.66.141      | 1                  | 446                 |
| localhost.re                | 1    | 1     | 172.67.163.57     | 2                  | 634                 |
| daehepharma.com             | 1    | 1     |                   | 0                  | 734                 |
| ex-jw.org                   | 1    | 1     | 185.230.63.171    | 3                  | 432                 |
| us.tf                       | 1    | 1     |                   | 0                  | 738                 |
| informarexresistere.fr      | 1    | 1     | 178.32.143.165    | 1                  | 790                 |
| running-sigi.de             | 1    | 1     |                   | 0                  | 32                  |
| buynowfromusa.com           | 1    | 1     | 35.223.118.1      | 1                  | 1293                |
| pbprofile.com               | 1    | 1     |                   | 0                  | 223                 |
| fini.net                    | 1    | 1     | 198.57.192.137    | 1                  | 444                 |
| globalpoliticalspectrum.com | 1    | 1     |                   | 0                  | 214                 |
| 41latitude.com              | 1    | 1     |                   | 0                  | 254                 |
| zzxu.cn                     | 1    | 1     |                   | 0                  | 551                 |
| energybulbs.co.uk           | 1    | 1     | 23.227.38.32      | 1                  | 562                 |
| o-ov.com                    | 1    | 1     |                   | 0                  | 434                 |
| lozo.com                    | 1    | 1     | 107.21.144.47     | 2                  | 325                 |
| tottenhamhk.com             | 1    | 1     |                   | 0                  | 237                 |
| newstetic.com               | 1    | 1     | 104.21.3.241      | 2                  | 338                 |
| triggerfish.se              | 1    | 1     | 162.159.135.42    | 2                  | 543                 |

This data can be analysed through a script like in `part_B.py`. 
The outputs of the script on the current data are :

```
67 / 100 = 67.0 % queries were answered
33 / 100 = 33.0 % queries were not answered
average latency is 597.28 ms
average throughput is 1.67 requests/s
average latency for only answered queries is 626.03 ms
average throughput for only answered queries is 1.6 requests/s
```

Note that the percentage of queries that got answered are much lower than what one would expect consider the corruption and packet loss rates for the internet.
This actually happened because IITGN rate-limits WiFi usage, giving us only about 70% of queries being answered.
This figure of 70% is not a random number.

## Part C

To connect to the custom DNs resolver (`10.0.0.5`) , just like before, we can change the `/etc/resolve.conf` file.
Then, running a DNS server process on the `10.0.0.5` resolver (connecting to a root server explicitely via socket programming) will allow us to use tools like `nslookup` with our custom resolver.
Unfortunaly, there won't be much utility for doing that since `nslookup` would only be used by `nslookup.py` (a python module). 
Instead, we can use socket programming to directly connect the hosts/clients to the `10.0.0.5` DNS resolver.

This is done using the `dns.py` library that can be used in three modes :
- `ask` : This is basic iterative resolution done by the host that runs the script.
- `server` : The host running this process behaves as a resursive resolver. It waits for DNS queries by clients, then resolves them and returns the response.
- `client` : The client can send DNS request with different values of `RD` and a custom `Cache` flag (last bit in flags) that tells the server whether or not to do Caching.
There is also a `custom_lookup` function that behaves similar to the function in the `nslookup.py` module.


