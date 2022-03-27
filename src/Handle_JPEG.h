#pragma once
#include <iostream>
#include<fstream>
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include "Headers.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include "Exeptions.h"

class Handle_JPEG 
{
private:
  Link Ethernet;            //the struct of the Ethernet protocol header
  Pcap_pkthdr Ptk_header;   // the struct of the packet header

  bool find_Empty_Str(FILE* PtrFile, int Pkt_size, int& Count);                 //find the end of the HTTP header
  bool extract_JPEG(FILE* PtrFile, FILE* WriteFile, int& Count);                //find the begin marker of the JPEG
  void parse(FILE* PtrFile, FILE* WriteFile );                                  //parsing the .pcap file
  bool write_File(FILE* PtrFile, FILE* WriteFile, int Pkt_size, int& Count);    //writing the JPEG into the new file
  int handle_headers(unsigned short& Server_port, int Index, FILE* PtrFile, FILE* WriteFile, unsigned short& Src_port);
    
public:
  Handle_JPEG(FILE* PtrFile, FILE* WriteFile) 
  {
    try 
    {
      parse(PtrFile, WriteFile);
    }
    catch (Exeptions& obj) 
    {
      throw obj;
    }
  }
};

