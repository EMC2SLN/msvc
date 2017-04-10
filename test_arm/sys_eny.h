#pragma once
#include<stdio.h>

#pragma warning (disable: 4996) //e.g. fopen_s strcut_s...


//#pragma warning(disable: 4311) // pointer truncation
//#pragma warning(disable: 4312) // conversion problems
//#pragma warning(disable: 4748) // optimization disabled
//#pragma warning(disable: 4244)
//#pragma warning(disable: 4267)
//#pragma warning(disable: 4018)
//#pragma warning(disable: 4309)
//#pragma warning(disable: 4305)
//#pragma warning(disable: 4101)
//#pragma warning(disable: 4715)
extern "C" void _declspec(dllexport)  call_vm(char * _file_name, char * _out_file_name, char * _start_address, char * _end_address);