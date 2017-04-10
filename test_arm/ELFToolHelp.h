#pragma once
#include<windows.h>
#include<winnt.h>

#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
//#include<unistd.h>
#include <iosfwd>
#include<iomanip>
#include<vector>
#include <tchar.h>
using namespace std;
#define VM_START { 0xeb,0x00, 0x0C, 0x00, 0x4E, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4C, 0x00, 0x56, 0x00, 0x4D, 0x00, 0x53, 0x00, 0x54, 0x00,  0x41, 0x00, 0x52, 0x00, 0x54, 0x00, 0x00, 0x00}//28byte
#define VM_END   {0xeb, 0x00, 0x0c, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4c, 0x00, 0x56, 0x00, 0x4d, 0x00, 0x45, 0x00, 0x4e, 0x00,  0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
class ELFToolHelp
{
public:
	Elf32_Ehdr eh;

	Elf32_Shdr* sh_table;	/* section-header table is variable size */
	Elf32_Phdr* ph_table;
	ifstream file_handle;
	Elf32_Ehdr *elf_header;
	ifstream *file_hand;
	ofstream * writehand;
public:
	ELFToolHelp();
	void init();
	unsigned char* strhex = NULL;
	void read_elf_header();
	bool is_ELF();
	void print_elf_header();
	void read_program_headers();
	void print_program_headers();
	void read_section_headers();
	char *read_section(Elf32_Shdr sh);
	void print_section_headers();
	void print_symbol_table(Elf32_Shdr* sh_table, int symbol_table);
	void print_symbols();
	unsigned char* SearchSDK(DWORD &start_offset, DWORD &end_offset, int &len);
	DWORD get_section_index(DWORD _rva);
	int AddCodeSection(const char * section, DWORD _section_size, char* filename);
	void startSDKreduce(DWORD startadress, DWORD jumpadress, char* _file_name, char* jmpins);
	void SaveFile();//Î´ÊµÏÖ
	DWORD getaddresofnewsection(char* filename, DWORD _section_size);
	char*  d_value2jmpins(int d_value);
	void reduce(DWORD startadress, DWORD jumpadress, char* _file_name, char* jmpins);
	char* getnewsename()
	{
		return this->szSecname;
	}
	void setnewsename(char* newname = ".nisl")
	{
		this->szSecname = newname;
	}
	~ELFToolHelp() 
	{
		free(strhex);
	}
	// void print_string_hex(unsigned char *str, size_t len);
protected:
	char * szSecname = ".nisl";
private:

};


