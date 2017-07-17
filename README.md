# PcapNetworkFlow
* A very tiny programs to count out the TCP or UDP network flow in a pcap files.
* Using [libtins](http://libtins.github.io/) library.

## Features:
* Default print out all TCP network flow now.

## Usage:
    ./pcap_network_flow PCAP_FILE.pcap

## Dependencies:
- g++ (support C++11)
- cmake
- [libtins](http://libtins.github.io/)
    - you can use the **install_libtins.sh** script to build the libtins library.
- [libpcap](http://www.tcpdump.org/)
- [C++ boost](www.boost.org)
    - ...

## License:
- BSD-3
