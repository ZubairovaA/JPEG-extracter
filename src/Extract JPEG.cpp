// Extract JPEG.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
#include <iostream>
#include<fstream>
#include <stdio.h>
#include "Headers.h"
#include"Handle_JPEG.h"
 
int main(int argc, char* argv[]) 
{
  if (argc != 3)
  {
    std::cout << "You should enter exactly 2 files.";
    return 0;
  }
  FILE* PtrFile = nullptr;                       // the pointer to the file for reading
  FILE* WriteFile = nullptr;                     // the pointer to the file for writing
  errno_t Err = 0, ErrW = 0;                     //opening with mistake
  const char* File_Read = argv[1];               //"test.pcap";
  const char* File_Write = argv[2];              // "out.jpg.docx";

  Err = fopen_s(&PtrFile, File_Read, "rb");      //check for the correct opening of the reading file
  ErrW = fopen_s(&WriteFile, File_Write, "wb");  //check for the correct opening of the writing file
    
  if (ErrW != 0) 
  {
    std::cerr << "Can't open the file for writing";
    goto close_files;
  }
  if (Err == 0)                                   //if the reading file was opened correctly
  {                                
    try 
    {
      Handle_JPEG Obj(PtrFile, WriteFile);        //parse the .pcap file
    } 
    catch (Exeptions& obj) 
    {
      obj.Handle_Exeption(PtrFile, WriteFile, Err, ErrW);  //print the error messege and close writing and reading files
    }

    Err = fclose(PtrFile);                     //close reading file
    ErrW = fclose(WriteFile);                  //close writing file
  } 
  else 
  {
    std::cerr << "Can't open the file for reading";
    goto close_files;
  }

close_files:
  if (PtrFile)                                //if the reading file is still opened
  {                                 
    Err = fclose(PtrFile);
    if (Err == 0) 
    {
      std::cout << "The reading file was closed";
    }
  }

  if (WriteFile)                              //if the writing file is still opened
  {                               
    ErrW = fclose(WriteFile);
    if (ErrW == 0) 
    {
      std::cout << "The writing file was closed";
    }
  }

  return 0;
}

