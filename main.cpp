#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <regex>

using namespace std;

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

int threadCountInput = 1;
regex regexInput;

bool isNumber(string input){
    for(int i= 0; i < input.length(); i++){
        if(isdigit(input[i]) == false)
            return false;
    }

    return true;
}

bool isValidRegex(string input){

    try{
    regexInput = input;
    return true;
    }
    catch(...){
    return false;
    }
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct ether_header *ep;
    struct ip *iph;
    unsigned short ether_type;
    int chcnt = 0;
    int len = pkthdr->len;
    int i;

    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);

    if (ether_type == ETHERTYPE_IP) {


        packet += sizeof(struct ether_header);
        iph = (struct ip *)packet;

        string ipVersion = reinterpret_cast<char*>(iph->ip_v);
        string ipHeaderLen = reinterpret_cast<char*>(iph->ip_v);
        string sourceAddress = inet_ntoa(iph->ip_src);
        string destAddress = inet_ntoa(iph->ip_dst);
        int packetSize = len-16;

        if(regex_match(ipVersion, regexInput) || regex_match(ipHeaderLen, regexInput) || regex_match(sourceAddress, regexInput) || regex_match(destAddress, regexInput)) //Packet source or destination adress match with regular expression{
        {
            cout << "IP Ver" << ipVersion << endl;
            cout << "IP Header Len" << ipHeaderLen <<2;
            cout << "IP Source Address" << sourceAddress << endl;
            cout << "IP Dest Address" << destAddress << endl;
            cout << "IP Packet Size " << packetSize << endl;
        }
    }
}

int main(int argc, char* argv[])
{
    std::vector<std::string> allArgs(argv, argv + argc);

    if(argc != 3){
    cout << "You need to supply two arguments to this program. \nArgument 1: Regular Expression Pattern \nArgument 2: Thread Count" << endl;
    return -1;
    }
    else if(!isValidRegex(allArgs[1])){
    cout << "Regex Pattern is not valid" << endl;
    return -1;
    }
    else if(!isNumber(allArgs[2])){
    cout << "Thread Count is not valid" << endl;
    return -1;
    }
    else{
        regexInput = argv[1];
        threadCountInput = atoi(argv[2]);
    }

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        cout << "dev is null:" << errbuf << endl;
        return -1;
    }

    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    if(descr == NULL)
    {
        cout << "pcap_open_live():" << errbuf << endl;
        return -1;
    }

    pcap_loop(descr, -1 /*for infinitely loop*/, my_callback, NULL);

    return 0;
}
