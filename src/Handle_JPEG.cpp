#include "Handle_JPEG.h"

bool Handle_JPEG::find_Empty_Str(FILE* PtrFile, int Pkt_size, int& Count) 
{
  char Data[3] { '/0' };                     //array for raed bytes
  char Sample[3] = { '/n', '/n' };           //array for sample of empty string

  while (Count <= (Pkt_size)) 
  {
    fread(&Data, 2, 1, PtrFile);             //reading 2 bytes
    if (strcmp(Data, Sample) == 0)           //compare the read bytes and the sample
    {       
      return true;   
    }
    Count += 2;
  }
  return false;
}

bool Handle_JPEG::write_File(FILE* PtrFile, FILE* WriteFile, int Pkt_size, int& Count)
{
  byte* Buffer = new byte[(Pkt_size - Count)];                     //array for read bytes
  static int Written_Bytes = 0;                                    //count how many bytes should be written in the file

  fread(Buffer, (Pkt_size - Count), 1, PtrFile);                   //reading JPEG
  fwrite(Buffer, (Pkt_size - Count), 1, WriteFile);                //writing JPEG
  Written_Bytes += (Pkt_size - Count);                             

  if ((Buffer[(Pkt_size - Count - 1)] == 0xd9) && (Buffer[(Pkt_size - Count - 2)] == 0xff))       //check for the end of the JPEG 
  {     
     delete[] Buffer;
     int File_Size = ftell(WriteFile);
     if ((Written_Bytes + 2) != File_Size)                         //compare (written bytes + JPEG begin marker) and the size of the writing file in bytes 
     {                    
       std::cerr << "The JPEG file was not completly wtitten";
     }
     return true;
  } 
  else  
  {
    delete[] Buffer;
    return false;
  }
}

bool Handle_JPEG::extract_JPEG(FILE* PtrFile, FILE* WriteFile,  int&Count) 
{
  unsigned char JPEG_m[2];                         //array for read bytes
  fread(&JPEG_m, 2, 1, PtrFile);                   //reading
  Count += 2;                                      //moving the counter
    
  if ((JPEG_m[0] == 0xff) && (JPEG_m[1] == 0xd8))  //check for the beging marker of the JPEG
  {   
    fwrite(JPEG_m, 2, 1, WriteFile);
    return true;
  } 
  else
  {
    return false;
  }
}

int Handle_JPEG::handle_headers(unsigned short& Server_port, int Index, FILE* PtrFile, FILE* WriteFile, unsigned short& Src_port)
{
  try 
  {
    if (fread(&Ptk_header, 16, 1, PtrFile) == 0)                  //read the packet header 16 bytes
    {          
      throw Exeptions("Reading the packet header failed");
    }
    if (Ptk_header.len < Ptk_header.caplen)                         //check if the packet is complete
    {             
      throw Exeptions(Ptk_header.len, Ptk_header.caplen, Index);
    }
    if (fread(&Ethernet, 14, 1, PtrFile) == 0)                     //read the ethernet header
    {          
      throw Exeptions("Reading the link layer header failed");
    }

    Ethernet.VLAN_Protocol(PtrFile);                               //check for the VLAN protocol
    unsigned char Ip_tcp_length = 0;                               //the length of the IP(first) and TCP(second) headers    
    if (fread(&Ip_tcp_length, 1, 1, PtrFile) == 0)              //reading the IP header length
    {         
      throw Exeptions("Reading the IP header letgth failed");
    }
    int Ip_size = 4 * (Ip_tcp_length & 0x0F);                    //counting the IP header length 
    fseek(PtrFile, Ip_size - 1, SEEK_CUR);                       //moving to the source port in TCP header

    if (fread(&Src_port, 2, 1, PtrFile) == 0)                 //reading the source port
    {                  
      throw Exeptions("Reading the source port failed");
    }

    fseek(PtrFile, 10, SEEK_CUR);                                //moving to the TCP header length
    if (fread(&Ip_tcp_length, 1, 1, PtrFile) == 0) 
    {           
      throw Exeptions("Reading the TCP header letgth failed");
    }
    int TCP_size = (Ip_tcp_length >> 4) * 4;                                   //counting the TCP header length
    fseek(PtrFile, (TCP_size - 13), SEEK_CUR);                                 //moving the pointer to the payload
  }
  catch (Exeptions& obj)
  {
    throw obj;
  }
   return (Ptk_header.len - (sizeof(Ethernet) + Ip_size + TCP_size));         //the length of the payload
}

void Handle_JPEG::parse(FILE* PtrFile, FILE* WriteFile) 
{
  long Pkt_offset = 24;                 // the pcap file header  24 bytes
  unsigned short Server_port = 0;       // port of the server
  bool Empty_str = false;               // the empty string markes the end of the HTTP header 
  bool JPEG_Marker = false;             // JPEG begin marker
  bool JPEG_End = false;                // JPEG end marker 
  int Index = 1;                        // the number of the packet
  unsigned short Src_port = 0;          //the source port

  while (fseek(PtrFile, Pkt_offset, SEEK_SET) == 0) 
  {
    int Pkt_size = handle_headers(Server_port, Index, PtrFile, WriteFile, Src_port);
    int Count = 0;                                                             //counter of bytes in the payload

    if ((Server_port == 0) && (Pkt_size > 6))                                  //check for the HTTP protocol
    {                                
      char HTTP_begin[6] { '/0' };                                             //array for the read bytes
      char Res[6] = { 'H', 'T', 'T', 'P', '/' };                               //array for the sample

      fread(&HTTP_begin, 5, 1, PtrFile);

      if (strcmp(HTTP_begin, Res) == 0)                                        //if HTTP is found 
      {              
        Count = 6;
        Server_port = Src_port;                                                //marking the servers' port

        if ((Count + 1) <= Pkt_size) 
        {
          Empty_str = find_Empty_Str(PtrFile, Pkt_size, Count);                //find the end of the HTTP header

          if (((Count + 1) <= Pkt_size) && (Empty_str))                        //if the empty string is found
          {                         
            JPEG_Marker = extract_JPEG(PtrFile, WriteFile, Count);             //check for the JPEG begin marker
            if (JPEG_Marker)                                                   // if JPEG begin marker is found
            {                                                   
              JPEG_End = write_File(PtrFile, WriteFile, Pkt_size, Count);      //write the JPEG into the new file
              if (JPEG_End) 
              {                                                                //if JPEG is copmpleted
                break;
              }
            }
          }
        }   
      }
    } 
    else if ((!Empty_str) && (Src_port == Server_port) && (Pkt_size >= 2))        //if HTTP begining is found but the end of the HTTP header is not found yet
    {      
      Empty_str = find_Empty_Str(PtrFile, Pkt_size, Count);                       //find empty string
      if (((Count + 1) <= Pkt_size) && (Empty_str))                               //if empty string is found
      {                             
        JPEG_Marker = extract_JPEG(PtrFile, WriteFile, Count);                    //check for the JPEG begin marker
        if (JPEG_Marker)                                                          //if JPEG begin marker is found
        {                                                      
          JPEG_End = write_File(PtrFile, WriteFile, Pkt_size, Count);             //write the JPEG into the new file
          if (JPEG_End) 
          {
            break;
          }
        }
      }
    } 
    else if ((Empty_str) && (Src_port == Server_port) && (Pkt_size >= 2)) 
    {       
      if (!JPEG_Marker)                                                           //if the JPEG begin marker is not found yet
      {                                                        
        JPEG_Marker = extract_JPEG(PtrFile, WriteFile, Count);
        if (JPEG_Marker) 
        {
          JPEG_End = write_File(PtrFile, WriteFile, Pkt_size, Count);
          if (JPEG_End) 
          {
            break;
          }
        }
      } 
      else 
      {                                                                          //if the JPEG begin marker is already found
        JPEG_End = write_File(PtrFile, WriteFile, Pkt_size, Count);
        if (JPEG_End) 
        {
          break;
        }
      }
    }

    Index ++;                                                                   //increment the number of the packet
    Pkt_offset += (16 + Ptk_header.caplen);                                     //move to the next packet
  }
}
