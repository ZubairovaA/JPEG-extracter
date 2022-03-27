#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

struct Pcap_pkthdr          // packet header struct
{        
  struct timeval ts;	      // time stamp    
  unsigned int caplen;	    // length of portion present 
  unsigned int len;	        // length of this packet (off wire) 
};


struct Link                           // Ethernet header struct
{                      
  unsigned char ether_dhost[6];       // MAC dest address
  unsigned char ether_shost[6];       // MAC source address
  unsigned short ether_type;          // next level protocol  

  void VLAN_Protocol(FILE* PtrFile);  //checking for the VLAN protocol
};

