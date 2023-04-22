import os, sys, subprocess, getopt
import binascii
import netifaces
from scapy.all import *
from library import *

def traceroute(target, dport=80, minttl=1, maxttl=30, stype="Random", srcport=50000, iface=None, l4=None, filter=None, timeout=5, verbose=None, gw=None, netproto="TCP", nquery=1, ptype=None, payload=b'', privaddr=0, rasn=1, **kargs):
    """A Traceroute command:
         traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [minttl=1,] [maxttl=1,] [iface=None]
             [l4=None,] [filter=None,] [nquery=1,] [privaddr=0,] [rasn=1,] [verbose=conf.verb])

              stype: Source Port Type: "Random" or "Increment".
            srcport: Source Port. Default: 50000.
                 gw: IPv4 Address of the Default Gateway.
           netproto: Network Protocol (One of: "TCP", "UDP" or "ICMP").
             nquery: Number of Traceroute queries to perform.
              ptype: Payload Type: "Disable", "RandStr", "RandStrTerm" or "Custom".
            payload: A byte object for each packet payload (e.g., b'\x01A\x0f\xff\x00') for ptype: 'Custom'.
           privaddr: 0 - Default: Normal display of all resolved AS numbers.
                     1 - Do not show an associated AS Number bound box (cluster) on graph for a private IPv4 Address.
               rasn: 0 - Do not resolve AS Numbers - No graph clustering.
                     1 - Default: Resolve all AS numbers.
             retry: If positive, how many times to resend unanswered packets
                    if negative, how many times to retry when no more packets
                    are answered.
           timeout: How much time to wait after the last packet has been sent."""
    # Initialize vars...
    trace = []			# Individual trace array
    # Range check number of query traces
    if nquery < 1:
        nquery = 1
    # Create instance of an MTR class...
    multi_traceroute = MTR(nquery=nquery, target=target)
    # Default to network protocol: "TCP" if not found in list...
    plist = ["TCP", "UDP", "ICMP"]
    netproto = netproto.upper()
    if netproto not in plist:
        netproto = "TCP"
    multi_traceroute._netprotocol = netproto
    # Default to source type: "Random" if not found in list...
    slist = ["Random", "Increment"]
    stype = stype.title()
    if stype not in slist:
        stype = "Random"
    if stype == "Random":
        sport = RandShort()  # Random
    elif stype == "Increment":
        if srcport != None:
            sport = IncrementalValue(start=(srcport - 1), step=1, restart=65535)  # Increment
    # Default to payload type to it's default network protocol value if not found in list...
    pllist = ["Disabled", "RandStr", "RandStrTerm", "Custom"]
    if ptype is None or (not ptype in pllist):
        if netproto == "ICMP":
            ptype = "RandStr"	   # ICMP: A random string payload to fill out the minimum packet size
        elif netproto == "UDP":
            ptype = "RandStrTerm"  # UDP: A random string terminated payload to fill out the minimum packet size
        elif netproto == "TCP":
            ptype = "Disabled"	   # TCP: Disabled -> The minimum packet size satisfied - no payload required
    # Set trace interface...
    if not iface is None:
        multi_traceroute._iface = iface
    else:
        multi_traceroute._iface = conf.iface
    # Set Default Gateway...
    if not gw is None:
        multi_traceroute._gw = gw
    # Set default verbosity if no override...
    if verbose is None:
        verbose = conf.verb
    # Only consider ICMP error packets and TCP packets with at
    # least the ACK flag set *and* either the SYN or the RST flag set...
    filterundefined = False
    if filter is None:
        filterundefined = True
        filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    # Resolve and expand each target...
    ntraces = 0		# Total trace count
    exptrg = []		# Expanded targets
    for t in target:
        # Use scapy's 'Net' function to expand target...
        et = [ip for ip in iter(Net(t))]
        exptrg.extend(et)
        # Map Host Names to IP Addresses and store...
        if t in multi_traceroute._host2ip:
            multi_traceroute._host2ip[t].extend(et)
        else:
            multi_traceroute._host2ip[t] = et
        # Map IP Addresses to Host Names and store...
        for a in et:
            multi_traceroute._ip2host[a] = t
    # Store resolved and expanded targets...
    multi_traceroute._exptrg = exptrg
    # Traceroute each expanded target value...
    if l4 is None:
        # Standard Layer: 3 ('TCP', 'UDP' or 'ICMP') tracing...
        for n in range(0, nquery):                              # Iterate: Number of queries
            for t in exptrg:                                    # Iterate: Number of expanded targets
                # Execute a traceroute based on network protocol setting...
                if netproto == "ICMP":
                    # MTR Network Protocol: 'ICMP'
                    tid = 8				        # Use a 'Type: 8 - Echo Request' packet for the trace:
                    id = 0x8888					# MTR ICMP identifier: '0x8888'
                    seq = IncrementalValue(start=(minttl - 2), step=1, restart=-10)  # Use a Sequence number in step with TTL value
                    if filterundefined:
                        # Update Filter -> Allow for ICMP echo-request (8) and ICMP echo-reply (0) packet to be processed...
                        filter = "(icmp and (icmp[0]=8 or icmp[0]=0 or icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        icmp = ICMP(type=tid, id=id, seq=seq)
                        ipicmp = ip / icmp
                        a, b = sr(ipicmp, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each ICMP packet:
                            # Length of 'IP()/ICMP()' = 28, Minimum Protocol Data Unit (PDU) is = 46 -> Therefore a
                            # payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        # ICMP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        icmp = ICMP(type=tid, id=id, seq=seq)
                        raw = Raw(load=pload)
                        ipicmpraw = ip  / icmp / raw
                        a, b = sr(ipicmpraw, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                elif netproto == "UDP":
                    # Network Protocol: 'UDP'
                    if filterundefined:
                        filter += " or udp"			# Update Filter -> Allow for processing UDP packets
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        udp = UDP(sport=sport, dport=dport)
                        ipudp = ip / udp
                        a, b = sr(ipudp, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each UDP packet:
                            # Length of 'IP()/UDP()' = 28, Minimum PDU is = 46 -> Therefore a payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        # UDP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        udp = UDP(sport=sport, dport=dport)
                        raw = Raw(load=pload)
                        ipudpraw = ip  / udp / raw
                        a, b = sr(ipudpraw, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                else:
                    # Default MTR Network Protocol: 'TCP'
                    # Note: The minimum PDU size of 46 is statisfied with the use of TCP options.
                    # Use an integer encoded microsecond timestamp for the TCP option timestamp for each trace sequence.
                    uts = int(time.clock_gettime(time.CLOCK_REALTIME))
                    opts = [('MSS', 1460), ('NOP', None), ('Timestamp', (uts, 0)), ('WScale', 7)]
                    seq = RandInt()		# Use a start random TCP sequence number
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        tcp = TCP(seq=seq, sport=sport, dport=dport, options=opts)
                        iptcp = ip  / tcp
                        a, b = sr(iptcp, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            pload = RandString(size=32)	                 # Use a 32 byte random string
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=32, term=b'\n')  # Use a 32 byte random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        # TCP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        tcp = TCP(seq=seq, sport=sport, dport=dport, options=opts)
                        raw = Raw(load=pload)
                        iptcpraw = ip  / tcp / raw
                        a, b = sr(iptcpraw, iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                # Create an 'MTracerouteResult' instance for each result packets...
                trace.append(MTracerouteResult(res=a.res))
                multi_traceroute._res.append(a)		# Store Response packets
                multi_traceroute._ures.append(b)		# Store Unresponse packets
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    else:
        # Custom Layer: 4 tracing...
        filter = "ip"
        for n in range(0, nquery):
            for t in exptrg:
                # Run traceroute...
                a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / l4,
                          iface=iface, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                trace.append(MTracerouteResult(res=a.res))
                multi_traceroute._res.append(a)
                multi_traceroute._ures.append(b)
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    # Store total trace run count...
    multi_traceroute._ntraces = ntraces
    # Get the trace components...
    # for n in range(0, ntraces):
    for n in range(0, multi_traceroute._ntraces):
        trace[n].get_trace_components(multi_traceroute, n)
    # Compute any Black Holes...
    multi_traceroute.get_black_holes()
    # Compute Trace Hop Ranges...
    multi_traceroute.compute_hop_ranges()
    # Resolve AS Numbers...
    if rasn:
        multi_traceroute.get_asns(privaddr)
        # Try to guess ASNs for Traceroute 'Unkown Hops'...
        multi_traceroute.guess_unk_asns()
    # Debug: Print object vars at verbose level 8...
    if verbose == 8:
        print("multi_traceroute._target (User Target(s)):")
        print("=======================================================")
        print(multi_traceroute._target)
        print("\nmulti_traceroute._exptrg (Resolved and Expanded Target(s)):")
        print("=======================================================")
        print(multi_traceroute._exptrg)
        print("\nmulti_traceroute._host2ip (Target Host Name to IP Address):")
        print("=======================================================")
        print(multi_traceroute._host2ip)
        print("\nmulti_traceroute._ip2host (Target IP Address to Host Name):")
        print("=======================================================")
        print(multi_traceroute._ip2host)
        print("\nmulti_traceroute._res (Trace Response Packets):")
        print("=======================================================")
        print(multi_traceroute._res)
        print("\nmulti_traceroute._ures (Trace Unresponse Packets):")
        print("=======================================================")
        print(multi_traceroute._ures)
        print("\nmulti_traceroute._ips (Trace Unique IPv4 Addresses):")
        print("=======================================================")
        print(multi_traceroute._ips)
        print("\nmulti_traceroute._rt (Individual Route Traces):")
        print("=======================================================")
        print(multi_traceroute._rt)
        print("\nmulti_traceroute._rtt (Round Trip Times (msecs) for Trace Nodes):")
        print("=======================================================")
        print(multi_traceroute._rtt)
        print("\nmulti_traceroute._hops (Traceroute Hop Ranges):")
        print("=======================================================")
        print(multi_traceroute._hops)
        print("\nmulti_traceroute._tlblid (Target Trace Label IDs):")
        print("=======================================================")
        print(multi_traceroute._tlblid)
        print("\nmulti_traceroute._ports (Completed Targets & Ports):")
        print("=======================================================")
        print(multi_traceroute._ports)
        print("\nmulti_traceroute._portsdone (Completed Trace Routes & Ports):")
        print("=======================================================")
        print(multi_traceroute._portsdone)
        print("\nconf.L3socket (Layer 3 Socket Method):")
        print("=======================================================")
        print(conf.L3socket)
        print("\nconf.AS_resolver Resolver (AS Resolver Method):")
        print("=======================================================")
        print(conf.AS_resolver)
        print("\nmulti_traceroute._asns (AS Numbers):")
        print("=======================================================")
        print(multi_traceroute._asns)
        print("\nmulti_traceroute._asds (AS Descriptions):")
        print("=======================================================")
        print(multi_traceroute._asds)
        print("\nmulti_traceroute._unks (Unknown Hops IP Boundary for AS Numbers):")
        print("=======================================================")
        print(multi_traceroute._unks)
        print("\nmulti_traceroute._iface (Trace Interface):")
        print("=======================================================")
        print(multi_traceroute._iface)
        print("\nmulti_traceroute._gw (Trace Default Gateway IPv4 Address):")
        print("=======================================================")
        print(multi_traceroute._gw)

    return multi_traceroute

def usage():
  print('main.py -t || --targets <Target Host List> [-r || --retry <Retry>] [--timeout <Fractional Seconds>]')
  print('             [--netproto <Network Protocol>] [--stype <Type> [--sport <Source Port>]]')
  print('             [-p || --dports <Destination Service Ports>]')
  print('             [--minttl <Min TTL>] [--maxttl <Max TTL>] [--gateway <IPv4 Address>]')
  print('             [-g || --graphic <Graphic Type>] [-s || --showpadding] [--privaddr]')
  print('             [-f || --dirfile <SVG Directory File Name>] -i | --interface <Interface Name>')
  print('             [--ptype <Type> [--payload <Payload>]]')
  print('             [-q || --nquery <Query Trace Count>]')
  print('             [-a || --asnresolver <ASN Resolver>] [ --vspread <Vertical Node Separation>] [--rtt]')
  print('             [--title <Title Text>] [-v || --verbose <level>] [-h || --help]\n')
  print('* Where <Target Host List> and <Destination Ports> are a comma separated string. The <Target Host List> can be in CIDR notation format.')
  print('* Use the (--netproto) option to specify the MTR Network Protocol (Must be one of: "TCP" (Default), "UDP", or "ICMP").')
  print('* Use the (--stype) option to choose the source port type: "Random" (Default) or "Increment".')
  print('* Use the (--sport) option to specify a source port (Default: 50000) for source port type: "Increment".')
  print('  If the source port type: "--stype Increment" is used, then the source port will be increased by one (1) for')
  print('  each packet sent out during an MTR session.')
  print('* Use the (--ptype) option to choose the a packet payload type: "Disabled" (TCP Default) "RandStrTerm" (UDP Default),')
  print(' "RandStr" (ICMP Default), "ASCII" or "ASCII-Hex".')
  print("* Use the (--payload) option for a ASCII string value (e.g., \'Data1: 56\\n\') for ptype: \"ASCII\".")
  print("* Use the (--payload) option for a ASCII-Hex string value (e.g., \'01fe44fFEf\') for ptype: \"ASCII-Hex\".")
  print('  The "--payload ASCII-Hex" option must use 2 ASCII characters to represent one Hexadecimal byte: "f" => "0F" or "0f".')
  print('* To add additional TCP destination service ports for tracerouting: "80,443" (Default: "80").')
  print('* Use the (-s || --showpadding) to display packets with padding as red triangles.')
  print('* The (-a || --asnresolver) option can be: "Disabled", "All", "whois.cymru.com", "riswhois.ripe.net" or "whois.ra.net".')
  print('* Use the (--privaddr) option to disable showing an associated AS Number bound box (cluster)')
  print('  on the Multi-Traceroute graph for a private IPv4 Address.')
  print('* Use the (--timeout) option to limit the time waiting for a Hop packet response (Default: 5.0 seconds).')
  print('* Use the (-q || --nquery) count for the number of traces to perform per service target (Default: 1).')
  print('* The default graphic type is an SVG graphic: "svg".')
  print('* The default directory file name for the resulting mtr graphic: "./graph.svg".')
  print('* Use the (-f || --dirfile) option to change the resulting output directory:')
  print('  Example: "-f /var/nst/wuiout/scapy/graph.svg" - Output directory: "/var/nst/wuiout/scapy".')
  print('* The default Network Interface will be used to send out the traceroute unless the (-i || --interface) option is used.')
  print('* Use the (--gateway) option to override the detected gateway address.')
  print('* Increase the verbosity output with a level of 1 or more (Default: 0).')
  print('* Use the (--vspread) option to set the Vertical Separation in inches between nodes (Default: 0.75in).')
  print('* Use the (--rtt) option to display Round-Trip Times (msec) on the graphic for each Hop along a Traceroute.')
  print('* Use the (--title) option to override the default Title value: "Traceroute".')
  print('*** Example:')
  print('sudo python3 main.py -t "google.com,facebook.com,40.89.244.232,98.136.144.138,52.32.76.121,tiktok.com,store.steampowered.com,play.google.com,epicgames.com,netflix.com,fr.bandainamcoent.eu" -r 0 --timeout 0.1 --netproto "TCP" -p "80,443" --minttl 1 --maxttl 20 -q 2 -a "All" --rtt -v 1 --ptype ASCII --payload "DATA1: 1260";\n')

def main(argv):
  targets = []
  retry = -2
  timeout = 5.0
  netprotocol = "TCP"
  srcporttype = "Random"
  srcport = 50000
  dstports = [80]
  minttl = 1
  maxttl = 30
  payloadtype = None
  payload = ""
  verboselvl = 0
  graphictype = 'svg'
  dirfilenamebase = "./graph."
  dirfilename = ""
  nic = ""
  gateway = ""
  showpadding = 0
  nquery = 1
  asnresolver = "All"
  rasn = 1
  privaddr = 0
  vspread = 0.75
  title = "Traceroute"
  timestamp = ""
  rtt = 0

  try:
    opts, args = getopt.getopt(argv, "hv:t:r:p:g:sq:f:i:w:a:", ["version", "help", "verbose=", "targets=", "retry=", "timeout=", "dports=", "minttl=", "maxttl=", "graphic=", "showpadding", "nquery=", "dirfile=", "interface=", "privaddr", "asnresolver=", "vspread=", "title=", "ts=", "rtt", "netproto=", "gateway=", "stype=", "sport=", "ptype=", "payload="])
  except getopt.GetoptError:
    print('\n***ERROR*** An invalid command line argument was entered.')
    usage()
    sys.exit(1)
  for opt,arg in opts:
    if opt in ("--version"):
       print('ROUT 2022-2023 Project from Sorbonne Université by Thierry UNG/Jack Thay version 1.0')
       sys.exit(0)
    if opt in ("-h", "--help"):
      usage()
      sys.exit(0)
    elif opt in ("-v", "--verbose"):
      verboselvl = int(arg)
    elif opt in ("-t", "--targets"):
      hl = arg
      targets = hl.split(',')
    elif opt in ("-r", "--retry"):
      rt = int(arg)
      retry = -rt			# Set to negative for how many times to retry when no more packets are answered
    elif opt in ("--timeout"):
      timeout = float(arg)
    elif opt in ("--netproto"):
      netprotocol = arg.upper()
    elif opt in ("--stype"):
      srcporttype = arg.title()
    elif opt in ("--sport"):
      srcport = int(arg)
      if ((srcport < 0) or (srcport >= 2**16)):
        srcport = 50000			# Set to a default value if out of range
    elif opt in ("-p", "--dports"):
      dp = arg
      dps = dp.split(',')
      dstports = [int(p) for p in dps] 	# Use a list comprehension to convert port value from string to integer
    elif opt in ("--ptype"):
      payloadtype = arg
    elif opt in ("--payload"):
      payload = arg
    elif opt in ("--minttl"):
      minttl = int(arg)
      if (minttl <= 0):
        minttl = 1
    elif opt in ("--maxttl"):
      maxttl = int(arg)
      if (maxttl <= 0):
        maxttl = 20
    elif opt in ("-g", "--graphic"):
      graphictype = arg
    elif opt in ("-s", "--showpadding"):
      showpadding = 1
    elif opt in ("--asnresolver"):
      asnresolver = arg
    elif opt in ("--privaddr"):
      privaddr = 1
    elif opt in ("-q", "--nquery"):
      nquery = int(arg)
      if (nquery < 1):
        nquery = 1
    elif opt in ("-f", "--dirfile"):
      dirfilename = arg
    elif opt in ("-i", "--interface"):
      nic = arg
    elif opt in ("--gateway"):
      gateway = arg
    elif opt in ("--vspread"):
      vspread = float(arg)
    elif opt in ("--title"):
      title = arg
    elif opt in ("--rtt"):
      rtt = 1
  # Auto file name cration...
  if (dirfilename == ""):
    dirfilename = dirfilenamebase + graphictype
  # Range check Min/Max TTl counts...
  if (minttl > maxttl):
    maxttl = minttl
  # Validate the Network Protocol value...
  plist = ["TCP", "UDP", "ICMP"]
  if not netprotocol in plist:
    print('\n***ERROR*** Option: "--netproto" (Network Protocol) must be one of: "TCP", "UDP" or "ICMP".\n')
    usage()
    sys.exit(2)
  # Validate the Source Port type...
  slist = ["Random", "Increment"]
  if not srcporttype in slist:
    print('\n***ERROR*** Option: "--stype" (Source Port Type) must be one of: "Random" or "Increment".\n')
    usage()
    sys.exit(2)
  # Default to payload type to it's default network protocol value if not found in list...
  pllist = ["Disabled", "RandStr", "RandStrTerm", "ASCII", "ASCII-Hex"]
  if payloadtype is None or (not payloadtype in pllist):
    if (netprotocol == "ICMP"):
      payloadtype = "RandStr"		# ICMP: A random string payload to fill out the minimum packet size
    elif (netprotocol == "UDP"):
      payloadtype = "RandStrTerm"	# UDP: A random string terminated payload to fill out the minimum packet size
    elif (netprotocol == "TCP"):
      payloadtype = "Disabled"		# TCP: Disabled -> The minimum packet size satisfied - no payload required
  # Create byte object for the payload...
  if (payloadtype == 'ASCII'):
    payload = bytes(payload, 'utf-8')
    payloadtype = "Custom"		# Set custom payload type for mtr
  elif (payloadtype == 'ASCII-Hex'):
    # Convert ASCII-Hex to a byte object with 'binascii.unhexlify()':
    try:
      payload = binascii.unhexlify(payload)
      payloadtype = "Custom"
    except:
      print('\n***ERROR*** Option: ASCII-Hex Payload error: "Non-Hexadecimal" or "Odd-length" payload.\n', sys.exc_info()[0])
      usage()
      sys.exit(2)
  else:
    payload = b''			# Set empty byte object for non-custom payloads
  # Determine the default Gateway IPv4 Address...
  if (gateway == ''):
    gws = netifaces.gateways()
    defgw = gws['default'][netifaces.AF_INET]
    if (len(defgw) > 0):
      gateway = defgw[0]		# Set the default Gateway IPv4 Address 
  # Check ASN resolver value...
  # Set the Global config value: conf.AS_resolver to the desired ASN resolver...
  if asnresolver in ("Disabled"):
    rasn = 0					# Disable ASN resolving...
  elif asnresolver in ("All"):
    conf.AS_resolver = AS_resolver_multi()	# Use all AS resolvers...
    rasn = 1
  elif asnresolver in (""):
    conf.AS_resolver = AS_resolver_cymru()
    rasn = 1
  elif asnresolver in ("riswhois.ripe.net"):
    conf.AS_resolver = AS_resolver_riswhois()
    rasn = 1
  elif asnresolver in ("whois.ra.net"):
    conf.AS_resolver = AS_resolver_radb()
    rasn = 1
  else:
    print('\n***ERROR*** Option (--asnresolver) must be one of: "Disabled", "All",')
    print('            "whois.cymru.com", "riswhois.ripe.net" or "whois.ra.net".\n')
    usage()
    sys.exit(2)
  # Target Host list: A Manditory argument...
  if (len(targets) == 0):
    print('\n***ERROR*** A target host list (-t <Target Host List>) is required.')
    usage()
    sys.exit(2)

  if (verboselvl >= 1):
    sp = 'stype = "{t:s}", '.format(t = srcporttype)
    if (srcporttype != 'Random'):
      sp += 'srcport = {p:d}, '.format(p = srcport)
    if (nic == ''):
      print('\nmulti_traceroute = traceroute({a1:s}, retry = {a2:d}, timeout = {a3:.2f}, netproto = "{a4:s}", {a5:s}dport = {a6:s}, minttl = {a7:d}, maxttl = {a8:d}, nquery = {a9:d}, privaddr = {a10:d}, rasn = {a11:d}, gw = "{a12:s}", ptype = "{a13:s}", payload = {a14:s}, verbose = {a15:d})'.format(a1 = str(targets), a2 = retry, a3 = timeout, a4 = netprotocol, a5 = sp, a6 = str(dstports), a7 = minttl, a8 = maxttl, a9 = nquery, a10 = privaddr, a11 = rasn, a12 = gateway, a13 = payloadtype, a14 = repr(payload), a15 = verboselvl))
    else: 
      print('\nmulti_traceroute = traceroute({a1:s}, retry = {a2:d}, timeout = {a3:.2f}, netproto = "{a4:s}", {a5:s}dport = {a6:s}, minttl = {a7:d}, maxttl = {a8:d}, nquery = {a9:d}, privaddr = {a10:d}, rasn = {a11:d}, gw = "{a12:s}", ptype = "{a13:s}", payload = {a14:s}, iface = "{a15:s}", verbose = {a16:d})'.format(a1 = str(targets), a2 = retry, a3 = timeout, a4 = netprotocol, a5 = sp, a6 = str(dstports), a7 = minttl, a8 = maxttl, a9 = nquery, a10 = privaddr, a11 = rasn, a12 = gateway, a13 = payloadtype, a14 = repr(payload), a15 = nic, a16 = verboselvl))
  # Run multi_traceroute...
  try:
    if (nic == ''):
      multi_traceroute = traceroute(targets, retry = retry, timeout = timeout, netproto = netprotocol, stype = srcporttype, srcport = srcport, dport = dstports, minttl = minttl, maxttl = maxttl, nquery = nquery, privaddr = privaddr, rasn = rasn, gw = gateway, ptype = payloadtype, payload = payload, verbose = verboselvl)
    else:
      multi_traceroute = traceroute(targets, retry = retry, timeout = timeout, netproto = netprotocol, stype = srcporttype, srcport = srcport, dport = dstports, minttl = minttl, maxttl = maxttl, nquery = nquery, privaddr = privaddr, rasn = rasn, gw = gateway, ptype = payloadtype, payload = payload, iface = nic, verbose = verboselvl)
  except:
    print('\n**ERROR*** The Traceroute function failed. Use the verbose output option to help debug.')
    usage()
    sys.exit(3)

  if (verboselvl >= 1):
    tp = 0
    for ans in multi_traceroute._res:
      tp += len(ans)
    tp *= 2
    print('\nTrace Send/Receive Packet Summary (Total: {p:d} pkts):'.format(p = tp))
    print('=======================================================')
    print(multi_traceroute._res)
    utp = 0
    for uans in multi_traceroute._ures:
      utp += len(uans)
    print('\nTrace Unresponse Packet Summary (Total: {p:d} pkts):'.format(p = utp))
    print('=======================================================')
    print(multi_traceroute._ures)
  # Dump packet details at verbosity level 9...
  if (verboselvl >= 9):
    for t in range(0, multi_traceroute._nquery):
      rlen = len(multi_traceroute._res[t])
      if (rlen > 0):
        print('\nTrace Send/Receive Packet Details:')
        print('=======================================================')
        for i in range(0, rlen):
          print('-------------------------------------------------------')
          print('Trace Sent: {x:d} - multi_traceroute._res[{t:d}][{r:d}][0]:'.format(x = (i + 1), t = t, r = i))
          print('-------------------------------------------------------')
          multi_traceroute._res[t][i][0].show()
          print('-------------------------------------------------------')
          print('Trace Received: {x:d} - multi_traceroute._res[{t:d}][{r:d}][1]:'.format(x = (i + 1), t = t, r = i))
          print('-------------------------------------------------------')
          multi_traceroute._res[t][i][1].show()
      ulen = len(multi_traceroute._ures[t])
      if (ulen > 0):
        print('\nTrace Unresponse Packet Details:')
        print('=======================================================')
        for i in range(0, ulen):
          print('-------------------------------------------------------')
          print('Trace Sent: {x:d} - multi_traceroute._ures[{t:d}][{u:d}]:'.format(x = (i + 1), t = t, u = i))
          print('-------------------------------------------------------')
          multi_traceroute._ures[t][i].show()
  # Create SVG Graphic...
  try:
    if (verboselvl >= 1):
      print('\nNow generating the resulting scapy traceroute {gt:s} graphic: "{df:s}"'.format(gt = graphictype.upper(), df = dirfilename))
      print('\nmulti_traceroute.graph(format = "{gt:s}", target = "{tr:s}", padding = {pd:d}, vspread = {vs:.2f}, title = "{ti:s}", timestamp = "{ts:s}", rtt = {rtt:d})'.format(gt = graphictype, tr = dirfilename, pd = showpadding, vs = vspread, ti = title, ts = timestamp, rtt = rtt))
    multi_traceroute.graph(format = graphictype, target = dirfilename, padding = showpadding, vspread = vspread, title = title, timestamp = timestamp, rtt = rtt)
  except:
    print('\n**ERROR*** scapy traceroute failed to produce a {gt:s} graphic.'.format(gt = graphictype.upper()))
    usage()
    sys.exit(4)
  # Clean exit...
  sys.exit(0)
# Run this script by the interpreter if not being imported...
if __name__ == "__main__":
  main(sys.argv[1:])
