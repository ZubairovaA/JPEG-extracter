#include "Headers.h"

void Link::VLAN_Protocol(FILE* PtrFile) 
{      
  if (ntohs(this->ether_type) == 0x8100)        // checking for the VLAN tag  
  {    
    fseek(PtrFile, 4, SEEK_CUR);            //if there is the VLAN tag, mooving the pointer for the 4 bytes to determinate the beginning of the ether type 
  }
}

