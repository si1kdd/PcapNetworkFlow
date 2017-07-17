/*
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * A little programs to parse the pcap files.
 * Counting out the tcp and udp network flows.
 *
 * Other features: (TODO)
 *      Parse packet timestamp, ttl etc.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <pcap.h>
#include <tins/tins.h>

#include "pcap_network_flow.h"

#define MB (1048576.0)
#define UNUSE(x) (void)(x)

using std::map;
using std::string;
using std::list;
using std::vector;
using std::cin;
using std::cout;

using Tins::SnifferConfiguration;
using Tins::FileSniffer;
using Tins::IP;
using Tins::DNS;
using Tins::TCP;
using Tins::UDP;
using Tins::RawPDU;
using Tins::PDU;
using Tins::Packet;

static long long udp_pkt_count = 0,
                 tcp_pkt_count = 0,
                 udp_pkt_size  = 0,
                 tcp_pkt_size  = 0;

static size_t    total_pkt_count = 0;

static list<FlowStat> tcpFlowPool;

static map<string, FlowStat*> tcpFlowState;
static map<string, string> resolverDB;

static vector<FlowStat> tcpFlowNoPool;
static vector<int> flowIndex;

static inline bool flow_pkt_count_compare(FlowStat a, FlowStat b);

static inline string resolver(string q);

static bool handle_tcp_flows(const IP *ip, const TCP *tcp, double curr_timestamp);

static bool handle_udp_flows(const IP *ip, const UDP *udp, double curr_timestamp);

static bool callback(const Packet &packet);

static void print_output();

int main(int argc, char *argv[])
{
        if (argc < 2) {
                std::cout << "[*] Usage: " << argv[0] << " PCAP_files\n";
                return -1;
        }
        try {
                SnifferConfiguration config;
                config.set_filter("tcp or udp");
                config.set_promisc_mode(false);
                // config.set_snap_len(65536);

                FileSniffer sniffer(argv[1], config);
                sniffer.sniff_loop(callback);

                print_output();

                return 0;
        }
        catch (std::exception& ex) {
                std::cerr << "[X] Error: " << ex.what() << '\n';
                return -1;
        }
}
