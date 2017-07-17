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

static inline bool flow_pkt_count_compare(FlowStat a, FlowStat b)
{
        return (a.get_packet_count() < b.get_packet_count());
}

static inline string resolver(string q)
{
        map<string, string>::iterator iter;
        if ((iter = resolverDB.find(q)) != resolverDB.end())
                return iter->second;
        // if the key q is not the last one in the db, return itself.
        return q;
}

static bool handle_tcp_flows(const IP *ip, const TCP *tcp, double curr_timestamp)
{
        FlowStat stat;

        const RawPDU* raw = tcp->find_pdu<RawPDU>();
        if (!raw)
                return true;
        tcp_pkt_count++;
        tcp_pkt_size += raw->payload_size();

        char src_to_dst[128];
        snprintf(src_to_dst, sizeof(src_to_dst),
                 "%s:%u ------ %s:%u",
                 ip->src_addr().to_string().c_str(),
                 tcp->sport(),
                 ip->dst_addr().to_string().c_str(),
                 tcp->dport());

        // Mark this flow.
        map<string, FlowStat*>::iterator iter;
        if ((iter = tcpFlowState.find(src_to_dst)) != tcpFlowState.end()) {
                auto flow_no = iter->second;
                flow_no->increase_packet_count();
                flow_no->add_packet_size(raw->payload_size());
                flow_no->add_duration(curr_timestamp);
                flow_no->mapping_timestamp_and_pkts(curr_timestamp, raw->payload_size());
                return true;
        }

        // Add this flow.
        stat.set_src_port(tcp->sport());
        stat.set_dst_port(tcp->dport());

        string src_addr = ip->src_addr().to_string();
        string dst_addr = ip->dst_addr().to_string();
        stat.set_src_addr(src_addr);
        stat.set_dst_addr(dst_addr);

        stat.increase_packet_count();
        stat.add_packet_size(raw->payload_size());
        stat.add_duration(curr_timestamp);
        stat.mapping_timestamp_and_pkts(curr_timestamp, raw->payload_size());

        // Push it into the pool
        // For further action like data plotting, skip here.
        tcpFlowPool.push_front(stat);
        tcpFlowState[src_to_dst] = &tcpFlowPool.front();
        return true;
        // Skip other features here, to be continued......
}

static bool handle_udp_flows(const IP *ip, const UDP *udp, double curr_timestamp)
{
        const RawPDU *raw = NULL;
        udp_pkt_count++;
        udp_pkt_size += udp->length();

        if (udp->sport() != 53 && udp->dport() != 53)
                return true;

        auto flag = (raw = udp->find_pdu<RawPDU>());
        if (flag != NULL) {
                DNS dns = raw->to<DNS>();
                if (dns.type() == dns.RESPONSE) {
                        for (const auto& d : dns.answers())
                        {
                                if (d.query_class() != dns.ANY &&
                                    d.query_class() != dns.IN) {
                                        continue;
                                }
                                if (d.query_type() != dns.A &&
                                    d.query_type() != dns.AAAA) {
                                        continue;
                                }
                                // save the DNS data.
                                const char *d_data = d.data().c_str();
                                resolverDB[d_data] = dns.queries().front().dname();
                        }
                }
                // Skip other features here, to be continued......
        }
        UNUSE(ip);
        UNUSE(curr_timestamp);
        return true;
}

static bool callback(const Packet &packet)
{
        const PDU *pdu  = packet.pdu();
        const IP  *ip   = pdu->find_pdu<IP>();
        if (ip == NULL)
                return true;

        // Ignore non IP packets, and non tcp, udp packet.
        // You can use Wireshark to do a checking, be careful the wrong packet.
        ++total_pkt_count;

        const TCP *tcp = NULL;
        const UDP *udp = NULL;

        struct timeval tv;
        tv.tv_sec  = packet.timestamp().seconds();
        tv.tv_usec = packet.timestamp().microseconds();

        // Formatting time structure, get minutes and seconds in floating point type.
        time_t pkt_time = tv.tv_sec;
        struct tm *now  = localtime(&pkt_time);

        char minutes[64], seconds[64];
        strftime(minutes, sizeof(minutes), "%M", now);
        strftime(seconds, sizeof(seconds), "%S", now);

        double min, sec = 0;
        min = std::strtod(minutes, NULL);
        sec = std::strtod(seconds, NULL);

        // Should do checking here, because of lazy ......

        double total_sec = min * 60 + sec;
        char time_str[128];
        snprintf(time_str, sizeof(time_str), "%lu.%06ld", (long)total_sec, tv.tv_usec);

        // string pass_str(time_str);
        // Try to pass double type here.
        double curr_time = std::strtod(time_str, NULL);

        if ((tcp = pdu->find_pdu<TCP>()) != NULL)
                return handle_tcp_flows(ip, tcp, curr_time);
        else if ((udp = pdu->find_pdu<UDP>()) != NULL)
                return handle_udp_flows(ip, udp, curr_time);

        return true;
}

static void print_output()
{
        tcpFlowPool.sort(flow_pkt_count_compare);
        cout << "# " << tcpFlowPool.size() << " TCP Flows identified\n";

        char pkt[]      = "Packet ";
        char pkt_size[] = "Packet Size (Bytes)";
        char src[]      = "Source";
        char dst[]      = "Destination";
        char delim[]    = "-->";
        char first_t[]  = "First";
        char last_t[]   = "Last";

        printf("# %6s | %10s  | %25s  %45s %20s %20s\n",
                        pkt, pkt_size, src, dst, first_t, last_t);
        printf("\n");

        list<FlowStat>::iterator iter;
        int no = 0;
        for (iter = tcpFlowPool.begin(); iter != tcpFlowPool.end(); iter++)
        {
                std::ostringstream src_conn;
                src_conn << resolver((*iter).get_src_addr()).c_str()
                         << ":"
                         << (*iter).get_src_port();

                std::ostringstream dst_conn;
                dst_conn << resolver((*iter).get_dst_addr()).c_str()
                         << ":"
                         << (*iter).get_dst_port();

                // Packet timestamp count should equal to packet count.
                uint32_t flow_timestamp_count = (*iter).get_TimeStamp_size();

                printf("(%3d) %-6lld %-15lld %-50s %-3s %-30s Occur: First: %-LF Last: %-LF\n",
                       no++,
                       (*iter).get_packet_count(),
                       (*iter).get_pkt_size(),
                       src_conn.str().c_str(),
                       delim,
                       dst_conn.str().c_str(),
                       (*iter).get_timestamp(0),
                       (*iter).get_timestamp(flow_timestamp_count - 1));

                // You can indexing the flow here if you wanna use it.
        }

        printf("\n");

        printf("[*] There are %10ld packets in the pcap files\n", total_pkt_count);
        printf("[*] Total TCP %10lld packets, Payload %5.5LF MB\n",
                        tcp_pkt_count, (long double)(tcp_pkt_size / MB));
        printf("[*] Total UDP %10lld packets, Payload %5.5LF MB\n",
                        udp_pkt_count, (long double)(udp_pkt_size / MB));
}


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
