#pragma once



#ifndef __ELFREADER_H_
#define __ELFREADER_H_

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <unistd.h>
//#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exception>
#include "elf.h"

using namespace std;

#define offsetof(s, m) (size_t)&(((s*)0)->m)

#define get_data(base, s, index) (*(s*)(base+index))	
/*  --�����ͷ�ļ�
#define EI_NIDENT 16
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Addr;
*/
typedef struct
{
	unsigned char   e_ident[EI_NIDENT];
	Elf32_Half      e_type;     //elf�ļ����� 1 ���ض�λ��2 ��ִ�У� 3 ����Ŀ���ļ�
	Elf32_Half      e_machine;  //�������
	Elf32_Word      e_version;  //�汾��Ϣ��һ��Ϊ1
	Elf32_Addr      e_entry;    //��ڵ�ַ
	Elf32_Off       e_phoff;    //����ͷƫ�Ƶ�ַ
	Elf32_Off       e_shoff;    //�α����ļ��е�ƫ�Ƶ�ַ
	Elf32_Word      e_flags;
	Elf32_Half      e_ehsize;   //elf�ļ�ͷ�Ĵ�С
	Elf32_Half      e_phentsize;
	Elf32_Half      e_phnum;
	Elf32_Half      e_shentsize; //�α��������Ĵ�С��һ��Ϊsizeof(Elf32_Shdr)
	Elf32_Half      e_shnum;    //�α�����������
	Elf32_Half      e_shstrndx; //�α��ַ������ڶα��е��±�
} Elf32_header;


//Elf ͷ�ļ�����
#define ELF_LENHT 		sizeof(Elf32_header)
#define Section_Lenth sizeof(Elf32_Shdr)
//�α�


class ElfReader
{
public:

	//��ȡelf�ļ�
	bool readFile(const char *filename);

	Elf32_Ehdr& getHeader() const;

	void printElfHeader() const;

	void printElfSection();

	void printElfSymbol();

	void printElfRelSym();

	void printElfDumpProgram();
	string chartoString(char*   buf, int   nArrSize);
	unsigned int  getFileSize() const;

	ElfReader(const char *filename);

	~ElfReader();

private:

	Elf32_header	elf_header;
	Elf32_Shdr 		*elf_section;

	char *start;
	int fd;     //���ļ�������
	unsigned int pos; //�ļ���ǰ�������ֽ���
	unsigned int file_size;
};

#endif
