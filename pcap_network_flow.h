#ifndef __PCAP_NETWORK_FLOW_H
#define __PCAP_NETWORK_FLOW_H

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <iostream>
#include <sstream>

#include <string>
#include <list>
#include <vector>
#include <map>

using std::string;
using std::vector;
using std::map;

class FlowStat {

private:
        string          src_addr;
        string          dst_addr;
        string          flow_name;      // Output filename using.
        uint32_t        ttl;
        uint16_t        src_port;
        uint16_t        dst_port;
        long long       packet_count;
        long long       packet_size;

        vector<long double>
                        TimeStamp;
        map<long double, uint32_t>
                        TimeWithPkt;

public:
        FlowStat(string src_addr = "",
                 string dst_addr = "",
                 uint16_t src_port = 0,
                 uint16_t dst_port = 0)
        {
                this->src_addr = src_addr;
                this->dst_addr = dst_addr;
                this->src_port = src_port;
                this->dst_port = dst_port;
                ttl = packet_count = packet_size = 0;

                TimeStamp.clear();
                TimeWithPkt.clear();
        }

        void set_src_addr(string s);
        void set_dst_addr(string d);
        void set_src_port(uint16_t sp);
        void set_dst_port(uint16_t dp);
        void set_ttl(uint8_t ttl);

        void increase_packet_count();
        void add_packet_size(long long size);
        void add_duration(long double dur);
        void mapping_timestamp_and_pkts(long double time, uint32_t pkt);

        uint16_t        get_src_port();
        uint16_t        get_dst_port();

        uint32_t        get_ttl();
        uint32_t        get_pkt_by_time(long double time);
        uint32_t        get_TimeStamp_size();

        long long       get_packet_count();
        long long       get_pkt_size();
        long double     get_timestamp(int index);

        string get_src_addr() const;
        string get_dst_addr() const;
        string get_flow_name() const;
};

inline string
FlowStat::get_src_addr() const
{
        return src_addr;
}

inline string
FlowStat::get_dst_addr() const
{
        return dst_addr;
}

inline string
FlowStat::get_flow_name() const
{
        return flow_name;
}

inline uint16_t
FlowStat::get_src_port()
{
        return src_port;
}

inline uint16_t
FlowStat::get_dst_port()
{
        return dst_port;
}

inline long double
FlowStat::get_timestamp(int index)
{
        return TimeStamp.at(index);
}

inline uint32_t
FlowStat::get_ttl()
{
        return ttl;
}

inline uint32_t
FlowStat::get_pkt_by_time(long double time)
{
        return TimeWithPkt[time];
}

inline uint32_t
FlowStat::get_TimeStamp_size()
{
        return TimeStamp.size();
}

inline long long
FlowStat::get_packet_count()
{
        return packet_count;
}

inline long long
FlowStat::get_pkt_size()
{
        return packet_size;
}

inline void
FlowStat::set_src_addr(string s)
{
        this->src_addr = s;
}

inline void
FlowStat::set_dst_addr(string d)
{
        this->dst_addr = d;
}

inline void
FlowStat::set_src_port(uint16_t sp)
{
        this->src_port = sp;
}

inline void
FlowStat::set_dst_port(uint16_t dp)
{
        this->dst_port = dp;
}

inline void
FlowStat::set_ttl(uint8_t ttl)
{
        this->ttl = ttl;
}

inline void
FlowStat::add_packet_size(long long size)
{
        packet_size += size;
}

inline void
FlowStat::add_duration(long double dur)
{
        TimeStamp.push_back(dur);
}

inline void
FlowStat::increase_packet_count()
{
        packet_count++;
}

inline void
FlowStat::mapping_timestamp_and_pkts(long double time, uint32_t pkt)
{
        this->TimeWithPkt[time] = pkt;
}

#endif /* __PCAP_NETWORK_FLOW_H */
