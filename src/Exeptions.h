#pragma once
#include<iostream>

class Exeptions 
{
private:
  const char* Str_error = "";     //string for error messege
	int x = 0, y = 0, index = 0;    // x- off wire recieved bytes, y- planed length of the packet
	char C_Str[80];               
	
public:
	Exeptions(const char* Error) : Str_error(Error) { };
	Exeptions(int X, int Y, int Index) : x(X), y(Y), index(Index) 
	{
		sprintf_s(C_Str, 80, "In the frame %d were recieved %d bytes instead of %d bytes", index, x, y);
		Str_error = C_Str;		
	}
	const char* getError() { return Str_error; }
	void Handle_Exeption(FILE* PtrFile, FILE* WriteFile, errno_t & Err, errno_t& ErrW) 
	{
		std::cerr << getError();                    //print error messege
		Err = fclose(PtrFile);                 //close reading file
		ErrW = fclose(WriteFile);              //close writing file
	}
};

