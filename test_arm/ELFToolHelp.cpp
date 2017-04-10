#include<stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <assert.h>
#include "elf.h"
#include<iomanip>
#include<vector>
#include <tchar.h>
#include "ELFToolHelp.h"
#include "sys_eny.h"
#include <bitset>
using namespace std;

#define ALIGN(P, ALIGNBYTES)  ( ((unsigned long)P + ALIGNBYTES -1)&~(ALIGNBYTES-1) )
ELFToolHelp::ELFToolHelp()
{
	file_hand = &file_handle;
	elf_header = &eh;
}
void ELFToolHelp::init()
{
	ph_table = new Elf32_Phdr[eh.e_phnum];
	sh_table = new Elf32_Shdr[eh.e_shnum];
}

void ELFToolHelp::read_elf_header()
{
	assert(elf_header != NULL);
	(*file_hand).seekg(0, ios::beg);
	(*file_hand).read((char *)elf_header, sizeof(Elf32_Ehdr));
}

bool ELFToolHelp::is_ELF()
{
	/* ELF magic bytes are 0x7f,'E','L','F'
	* Using  octal escape sequence to represent 0x7f
	*/
	if (!strncmp((char*)eh.e_ident, "\177ELF", 4)) {
		printf("ELF OK");
		/* IS a ELF file */
		return 1;
	}
	else {
		printf("ELF KO\n");
		/* Not ELF file */
		return 0;
	}
}

void ELFToolHelp::print_elf_header()
{
	printf("\n********************************************************************************\n");
	printf("*                                ELF HEADER                                    *\n");
	printf("********************************************************************************\n\n");

	/* Storage capacity class */
	printf("Storage class\t= ");
	switch (eh.e_ident[EI_CLASS])
	{
	case ELFCLASS32:
		printf("32-bit objects\n");
		break;

	case ELFCLASS64:
		printf("64-bit objects\n");
		break;

	default:
		printf("INVALID CLASS\n");
		break;
	}

	/* Data Format */
	printf("Data format\t= ");
	switch (eh.e_ident[EI_DATA])
	{
	case ELFDATA2LSB:
		printf("2's complement, little endian\n");
		break;

	case ELFDATA2MSB:
		printf("2's complement, big endian\n");
		break;

	default:
		printf("INVALID Format\n");
		break;
	}

	/* OS ABI */
	printf("OS ABI\t\t= ");
	switch (eh.e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:
		printf("UNIX System V ABI\n");
		break;

	case ELFOSABI_HPUX:
		printf("HP-UX\n");
		break;

	case ELFOSABI_ARM:
		printf("ARM\n");
		break;

	case ELFOSABI_STANDALONE:
		printf("Standalone (embedded) app\n");
		break;

	default:
		printf("Unknown (0x%x)\n", eh.e_ident[EI_OSABI]);
		break;
	}

	/* ELF filetype */
	printf("Filetype \t= ");
	switch (eh.e_type)
	{
	case ET_NONE:
		printf("N/A (0x0)\n");
		break;

	case ET_REL:
		printf("Relocatable\n");
		break;

	case ET_EXEC:
		printf("Executable\n");
		break;

	case ET_DYN:
		printf("Shared Object\n");
		break;
	default:
		printf("Unknown (0x%x)\n", eh.e_type);
		break;
	}

	/* ELF Machine-id */
	printf("Machine\t\t= ");
	switch (eh.e_machine)
	{
	case EM_NONE:
		printf("None (0x0)\n");
		break;

	case EM_386:
		printf("INTEL x86 (0x%x)\n", EM_386);
		break;

	case EM_ARM:
		printf("ARM (0x%x)\n", EM_ARM);
		break;
	default:
		printf("Machine\t= 0x%x\n", eh.e_machine);
		break;
	}

	/* Entry point */
	printf("Entry point\t= 0x%08x\n", eh.e_entry);

	/* ELF header size in bytes */
	printf("ELF header size\t= 0x%08x\n", eh.e_ehsize);

	/* Program Header */
	printf("\nProgram Header\t= ");
	printf("0x%08x\n", eh.e_phoff);				/* start */
	printf("\t\t  %d entries\n", eh.e_phnum);	/* num entry */
	printf("\t\t  %d bytes\n", eh.e_phentsize);	/* size/entry */

												/* Section header starts at */
	printf("\nSection Header\t= ");
	printf("0x%08x\n", eh.e_shoff);				/* start */
	printf("\t\t  %d entries\n", eh.e_shnum);	/* num entry */
	printf("\t\t  %d bytes\n", eh.e_shentsize);	/* size/entry */
	printf("\t\t  0x%08x (string table offset)\n", eh.e_shstrndx);

	/* File flags (Machine specific)*/
	printf("\nFile flags \t= 0x%08x\n", eh.e_flags);

	/* ELF file flags are machine specific.
	* INTEL implements NO flags.
	* ARM implements a few.
	* Add support below to parse ELF file flags on ARM
	*/
	int32_t ef = eh.e_flags;
	printf("\t\t  ");

	//if (ef & EF_ARM_RELEXEC)
	//	printf(",RELEXEC ");

	//if (ef & EF_ARM_HASENTRY)
	//	printf(",HASENTRY ");

	//if (ef & EF_ARM_INTERWORK)
	//	printf(",INTERWORK ");

	//if (ef & EF_ARM_APCS_26)
	//	printf(",APCS_26 ");

	//if (ef & EF_ARM_APCS_FLOAT)
	//	printf(",APCS_FLOAT ");

	//if (ef & EF_ARM_PIC)
	//	printf(",PIC ");

	printf("\n");	/* End of ELF header */
}

void ELFToolHelp::read_program_headers() {
	(*file_hand).seekg(eh.e_phoff, ios::beg);
	// En gros, ici, j'ai ph qui est un tableau de structure Elf32_Phdr. Je voudrais boucler
	// pour remplir chaque structure avec eh.e_phentsize bytes (taille d'une structure Elf32_Phdr)
	for (int i = 0; i < eh.e_phnum; i++) {
		(*file_hand).read((char *)&ph_table[i], sizeof(Elf32_Phdr));
	}
}

void ELFToolHelp::print_program_headers() {
	printf("\n********************************************************************************\n");
	printf("*                                 SEGMENTS                                     *\n");
	printf("********************************************************************************\n\n");

	printf("+---+----------+----------+----------+----------+----------+----+---------+\n");
	printf("|idx|offset    |vaddr     |paddr     |file size |mem size  |algn|name     |\n");
	printf("+---+----------+----------+----------+----------+----------+----+---------+\n");

	string p_types[] = { "PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE", "PT_SHLIB", "PT_PHDR", "PT_NUM" };
	string seg_name;
	for (int i = 0; i < eh.e_phnum; i++) {
		if (ph_table[i].p_type < sizeof(p_types)) {
			seg_name = p_types[ph_table[i].p_type];
		}
		else {
			seg_name = "UNKNOWN";
		}
		printf(" %03d ", i);
		printf("0x%08x ", ph_table[i].p_offset);
		printf("0x%08x ", ph_table[i].p_vaddr);
		printf("0x%08x ", ph_table[i].p_paddr);
		printf("0x%08x ", ph_table[i].p_filesz);
		printf("0x%08x ", ph_table[i].p_memsz);
		printf("%4d ", ph_table[i].p_align);
		printf("%s\t", seg_name.c_str());
		printf("\n");
		//printf("Offset\t= 0x%08x\n", ph[i].p_filesz);
	}
}

void ELFToolHelp::read_section_headers() {
	(*file_hand).seekg(eh.e_shoff, ios::beg);
	// En gros, ici, j'ai ph qui est un tableau de structure Elf32_Phdr. Je voudrais boucler
	// pour remplir chaque structure avec eh.e_phentsize bytes (taille d'une structure Elf32_Phdr)
	for (int i = 0; i < eh.e_shnum; i++) {
		(*file_hand).read((char *)&sh_table[i], sizeof(Elf32_Shdr));
	}
}

char * ELFToolHelp::read_section(Elf32_Shdr sh) {
	char *buff = new char[sh.sh_size];
	(*file_hand).seekg(sh.sh_offset, ios::beg);//节区的第一个字节与文件头部之间的偏移，设置文件流的指针位置
	(*file_hand).read(buff, sh.sh_size);
	return buff;
}

void ELFToolHelp::print_section_headers() {
	Elf32_Shdr string_section = sh_table[eh.e_shstrndx];
	char *buff = read_section(string_section);

	printf("\n********************************************************************************\n");
	printf("*                                 SECTIONS                                     *\n");
	printf("********************************************************************************\n\n");
	printf("+---+----------+----------+----------+----+----------+----------+--------------+\n");
	printf("|idx|offset    |load-addr |size      |algn|flags     |type      |section       |\n");
	printf("+---+----------+----------+----------+----+----------+----------+--------------+\n");

	for (int i = 0; i < eh.e_shnum; i++) {

		printf(" %03d ", i);
		printf("0x%08x ", sh_table[i].sh_offset);
		printf("0x%08x ", sh_table[i].sh_addr);
		printf("0x%08x ", sh_table[i].sh_size);
		printf("%4d ", sh_table[i].sh_addralign);
		printf("0x%08x ", sh_table[i].sh_flags);
		printf("0x%08x ", sh_table[i].sh_type);
		printf("%s\t", buff + sh_table[i].sh_name);
		printf("\n");
	}
}

void ELFToolHelp::print_symbol_table(Elf32_Shdr* sh_table, int symbol_table) {
	char *str_tbl;
	Elf32_Sym* sym_tbl;
	int i, symbol_count;

	sym_tbl = (Elf32_Sym*)read_section(sh_table[symbol_table]);

	/* Read linked string-table
	* Section containing the string table having names of
	* symbols of this section
	*/
	int str_tbl_ndx = sh_table[symbol_table].sh_link;
	str_tbl = read_section(sh_table[str_tbl_ndx]);

	symbol_count = (sh_table[symbol_table].sh_size / sizeof(Elf32_Sym));
	printf("%d symbols\n", symbol_count);
	printf("+---+----------+----+----+---------+\n");
	printf("|idx|value     |bind|type|name     |\n");
	printf("+---+----------+----+----+---------+\n");

	for (i = 0; i< symbol_count; i++) {
		//printf(" %03d ", i);
		//printf("0x%08x ", sym_tbl[i].st_value);
		//printf("0x%08x  ", sym_tbl[i].st_size);//大小
		//printf("0x%08x  ", sym_tbl[i].st_shndx);//所在的表节值索引

		//printf("0x%02x ", ELF32_ST_BIND(sym_tbl[i].st_info));
		//printf("0x%02x ", ELF32_ST_TYPE(sym_tbl[i].st_info));
		//printf("%s\n", (str_tbl + sym_tbl[i].st_name));
		if (!strcmp("main", (str_tbl + sym_tbl[i].st_name))) {
			printf("Found symbol\t\".main\"\n");
			char* buf;
			buf = new char[sym_tbl[i].st_size];
			printf("0x%08x \n", sym_tbl[i].st_value);
			printf("0x%08x  ", sym_tbl[i].st_size);

			(*file_hand).seekg(sym_tbl[i].st_value, ios::beg);
			(*file_hand).read(buf, sym_tbl[i].st_size);
			for (int j = 0; j < sym_tbl[i].st_size; j++)
			{
				printf("%02x", buf[i]);
			}
			break;
		}

	}

	printf("\n");
}

void ELFToolHelp::print_symbols() {

	printf("\n********************************************************************************\n");
	printf("*                                  SYMBOLS                                     *\n");
	printf("********************************************************************************\n\n");

	for (int i = 0; i < eh.e_shnum; i++) {
		if ((sh_table[i].sh_type == SHT_SYMTAB) || (sh_table[i].sh_type == SHT_DYNSYM)) {
			printf("[Section %03d] ", i);
			print_symbol_table(sh_table, i);
		}
	}
}


unsigned char* ELFToolHelp::SearchSDK(DWORD &start_offset, DWORD &end_offset,int &len)
{
	int i;
	char* sh_str;   /* section-header string-table is also a section. */
	char* buf;      /* buffer to hold contents of the .text section */
	char* hexcode;
	DWORD offset;
	/* Read section-header string-table */
	sh_str = read_section(sh_table[eh.e_shstrndx]);

	for (i = 0; i<eh.e_shnum; i++) {
		if (!strcmp(".text", (sh_str + sh_table[i].sh_name))) {
			printf("Found section\t\".text\"\n");
			printf("at offset\t0x%08x\n", sh_table[i].sh_offset);
			offset = sh_table[i].sh_offset;
			printf("of size\t\t0x%08x\n", sh_table[i].sh_size);
			break;
		}
	}

	(*file_hand).seekg(sh_table[i].sh_offset, ios::beg);
	buf = new char[sh_table[i].sh_size];
	(*file_hand).read(buf, sh_table[i].sh_size);
	//在这里插入sdk找寻代码
	char vm_start[29] = VM_START;
	char vm_end[29] = VM_END;
	int hexdig = 0;
	int k;
	int firstindex;
	int lastindex;
	int j = 0;
	for (k = 0; k < sh_table[i].sh_size; k++) {

		while (!(((int)buf[k + j]) ^ vm_start[j])) {
			j++;
		}
		if (j >= sizeof(vm_start) - 2) {
			firstindex = k + j;
			start_offset = k + offset;
			break;
		}
	}
	//找vm_end的起始位置
	for (k = k + j; k < sh_table[i].sh_size; k++) {
		j = 0;
		while (!(((int)buf[k + j]) ^ vm_end[j])) {
			j++;
		}
		if (j >= sizeof(vm_end) - 2) {
			lastindex = k - 1;
			end_offset = lastindex + offset;
			break;
		}
	}
	//存储关键代码段
	strhex = (unsigned char*)malloc((lastindex - firstindex + 1) * sizeof(unsigned char));
	len = lastindex - firstindex + 1;
	printf("cehsdddsdsdsheh %d", len);

	for (int p = 0, i = firstindex; i <= lastindex; i++, p++)
	{
		strhex[p] = buf[i];
		//////////////////////////////////////////////
		printf("%02x ", (int)buf[i] & 0xff);
		//////////////////////////////////////////////
	}
	return strhex;
}

DWORD ELFToolHelp::get_section_index(DWORD _rva)
{
	DWORD iC = 0;
	for (iC = 0; iC<eh.e_shnum; iC++)
	{
		if (_rva - sh_table[iC].sh_offset <= sh_table[iC].sh_size)
		{
			return iC;
		}
	}
	return -1;
}

int  ELFToolHelp::AddCodeSection(const char * section, DWORD _section_size, char* filename)
{
	char name[50];
	FILE *fdr, *fdw;
	char *base = NULL;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *t_phdr, *load1, *load2, *dynamic;
	Elf32_Shdr *s_hdr;
	int flag = 0;
	int i = 0;
	unsigned mapSZ = 0;
	unsigned nLoop = 0;
	unsigned int nAddInitFun = 0;
	unsigned int nNewSecAddr = 0;
	unsigned int nModuleBase = 0;
	memset(name, 0, sizeof(name));
	if (_section_size == 0)
	{
		return 0;
	}
	fdr = fopen(filename, "rb");
	strcpy(name, filename);
	if (strchr(name, '.'))
	{
		strcpy(strchr(name, '.'), "_new.so");
	}
	else
	{
		strcat(name, "_new");
	}
	fdw = fopen(name, "wb");
	if (fdr == NULL || fdw == NULL)
	{
		printf("Open file failed");
		return 1;
	}
	fseek(fdr, 0, SEEK_END);
	mapSZ = ftell(fdr);//源文件的长度大小  
	printf("mapSZ:0x%x\n", mapSZ);

	base = (char*)malloc(mapSZ * 2 + _section_size);//2*源文件大小+新加的Section size  
	printf("base 0x%x \n", base);

	memset(base, 0, mapSZ * 2 + _section_size);
	fseek(fdr, 0, SEEK_SET);
	fread(base, 1, mapSZ, fdr);//拷贝源文件内容到base  
	if (base == (void*)-1)
	{
		printf("fread fd failed");
		return 2;
	}

	//判断Program Header  
	ehdr = (Elf32_Ehdr*)base;
	t_phdr = (Elf32_Phdr*)(base + sizeof(Elf32_Ehdr));
	for (i = 0; i < ehdr->e_phnum; i++)
	{
		if (t_phdr->p_type == PT_LOAD)
		{
			//这里的flag只是一个标志位，去除第一个LOAD的Segment的值  
			if (flag == 0)
			{
				load1 = t_phdr;
				flag = 1;
				nModuleBase = load1->p_vaddr;//所有PT_LOAD类型的程序头都按照p_vaddr的值做升序排列的
				printf("load1 = %p, offset = 0x%x \n", load1, load1->p_offset);
				printf("p_vadder =0x%x\n ", load1->p_vaddr);

			}
			else
			{
				load2 = t_phdr;
				printf("load2 = %p, offset = 0x%x \n", load2, load2->p_offset);
			}
		}
		if (t_phdr->p_type == PT_DYNAMIC)
		{
			dynamic = t_phdr;
			printf("dynamic = %p, offset = 0x%x \n", dynamic, dynamic->p_offset);
		}
		t_phdr++;
	}

	//section header  
	s_hdr = (Elf32_Shdr*)(base + ehdr->e_shoff);
	//获取到新加section的位置，这个是重点,需要进行页面对其操作  
	printf("addr:0x%x\n", load2->p_paddr);


	nNewSecAddr = ALIGN(load2->p_paddr + load2->p_memsz - nModuleBase, load2->p_align);
	if (load1->p_filesz < ALIGN(load2->p_paddr + load2->p_memsz, load2->p_align))
	{
		printf("offset:%x\n", (ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum));
		//注意这里的代码的执行条件，这里其实就是判断section header是不是在文件的末尾
		if ((ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum) != mapSZ)
		{
			if (mapSZ + sizeof(Elf32_Shdr) * (ehdr->e_shnum + 1) > nNewSecAddr)
			{
				printf("无法添加节\n");
				return 3;
			}
			else
			{
				memcpy(base + mapSZ, base + ehdr->e_shoff, sizeof(Elf32_Shdr) * ehdr->e_shnum);//将Section Header拷贝到原来文件的末尾
				ehdr->e_shoff = mapSZ;
				mapSZ += sizeof(Elf32_Shdr) * ehdr->e_shnum;//加上Section Header的长度
				s_hdr = (Elf32_Shdr*)(base + ehdr->e_shoff);
				printf("ehdr_offset:%x", ehdr->e_shoff);
			}
		}
	}
	else
	{
		nNewSecAddr = load1->p_filesz;
		printf("%x   \n", nNewSecAddr);
	}
	int nWriteLen = nNewSecAddr + ALIGN(strlen(this->getnewsename()) + 1, 0x10) + _section_size;//添加section之后的文件总长度：原来的长度 + section name + section size
	printf("添加新节之后文件的总长度 %x\n", nWriteLen);

	char *lpWriteBuf = (char *)malloc(nWriteLen);//nWriteLen :最后文件的总大小
	memset(lpWriteBuf, 0, nWriteLen);
	//ehdr->e_shstrndx是section name的string表在section表头中的偏移值,修改string段的大小
	s_hdr[ehdr->e_shstrndx].sh_size = nNewSecAddr - s_hdr[ehdr->e_shstrndx].sh_offset + strlen(this->getnewsename()) + 1;
	strcpy(lpWriteBuf + nNewSecAddr, this->getnewsename());//添加section name,修改
	printf("%x   \n", nNewSecAddr);
	//以下代码是构建一个Section Header
	Elf32_Shdr newSecShdr = { 0 };
	newSecShdr.sh_name = nNewSecAddr - s_hdr[ehdr->e_shstrndx].sh_offset;
	newSecShdr.sh_type = SHT_PROGBITS;
	newSecShdr.sh_flags = SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR;
	nNewSecAddr += ALIGN(strlen(this->getnewsename()) + 1, 0x10);
	newSecShdr.sh_size = _section_size;
	newSecShdr.sh_offset = nNewSecAddr;
	newSecShdr.sh_addr = nNewSecAddr + nModuleBase;// sh_addr被映射到内存中的首地址， nModuleBase为？ sh_addr = sh_offset
	newSecShdr.sh_addralign = 4;

	//////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////
	//修改Program Header信息
	load1->p_filesz = nWriteLen;
	load1->p_memsz = nNewSecAddr + _section_size;
	load1->p_flags = 7;		//可读 可写 可执行

							//修改Elf header中的section的count值
	ehdr->e_shnum++;
	memcpy(lpWriteBuf, base, mapSZ);//从base中拷贝mapSZ长度的字节到lpWriteBuf
	memcpy(lpWriteBuf + mapSZ, &newSecShdr, sizeof(Elf32_Shdr));//将新加的Section Header追加到lpWriteBuf末尾

																//写文件
	fseek(fdw, 0, SEEK_SET);
	fwrite(lpWriteBuf, 1, nWriteLen, fdw);
	fseek(fdw, newSecShdr.sh_offset, SEEK_SET);
	fwrite(section, 1, _section_size, fdw);
	fclose(fdw);
	fclose(fdr);
	free(base);
	free(lpWriteBuf);

}


DWORD ELFToolHelp::getaddresofnewsection(char* filename, DWORD _section_size)
{
	char name[50];
	FILE *fdr;
	char *base = NULL;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *t_phdr, *load1, *load2, *dynamic;
	Elf32_Shdr *s_hdr;
	int flag = 0;
	int i = 0;
	unsigned mapSZ = 0;
	unsigned nLoop = 0;
	unsigned int nAddInitFun = 0;
	unsigned int nNewSecAddr = 0;
	unsigned int nModuleBase = 0;
	memset(name, 0, sizeof(name));//内存清空操作
	fopen_s(&fdr, filename, "rb");//从文件lpPath读取，存放fdr中
	strcpy_s(name, filename);//存name

	if (fdr == NULL)
	{
		printf("Open file failed");
	}
	fseek(fdr, 0, SEEK_END);//wirte文件指针指向最后

	mapSZ = ftell(fdr);//函数 ftell 用于得到文件位置指针当前位置相对于文件首的偏移字节数，也就是源文件的长度大小
	base = (char*)malloc(mapSZ + _section_size);//2*源文件大小+新加的Section size
	memset(base, 0, mapSZ + _section_size);
	fseek(fdr, 0, SEEK_SET);
	fread(base, 1, mapSZ, fdr);//按照字节将 拷贝源文件内容到base
	if (base == (void*)-1)
	{
		printf("fread fd failed");
	}

	//判断Program Header
	ehdr = (Elf32_Ehdr*)base;//文件头
	t_phdr = (Elf32_Phdr*)(base + sizeof(Elf32_Ehdr));//程序头地址
	for (i = 0; i < ehdr->e_phnum; i++)//程序头的个数为循环条件
	{
		if (t_phdr->p_type == PT_LOAD)//类型
		{
			//这里的flag只是一个标志位，去除第一个LOAD的Segment的值
			if (flag == 0)
			{
				load1 = t_phdr;
				flag = 1;
				nModuleBase = load1->p_vaddr;//虚拟入口地址
			}
			else
			{
				load2 = t_phdr;
			}
		}
		if (t_phdr->p_type == PT_DYNAMIC)
		{
			dynamic = t_phdr;
		}
		t_phdr++;
	}

	//section header
	s_hdr = (Elf32_Shdr*)(base + ehdr->e_shoff);
	//获取到新加section的位置，这个是重点,需要进行页面对齐操作
	nNewSecAddr = ALIGN(load2->p_paddr + load2->p_memsz - nModuleBase, load2->p_align);
	//nNewSecAddr = load2->p_paddr + load2->p_memsz - nModuleBase;
	nNewSecAddr += ALIGN(strlen(this->getnewsename()) + 1, 0x10);
	fclose(fdr);
	free(base);
	return nNewSecAddr;
}
void  ELFToolHelp::startSDKreduce(DWORD startadress, DWORD jumpadress, char* _file_name, char* jmpins)
{
	ofstream  writehand;
	char name[50];
	strcpy(name, _file_name);
	if (strchr(name, '.'))
	{
		strcpy(strchr(name, '.'), "_new.so");
	}
	writehand.open(name, ios::in | ios::out | ios::binary);
	writehand.seekp(startadress, ios::beg);
	writehand.write(jmpins, 4);//指令长度为4
	writehand.close();
}
void  ELFToolHelp::reduce(DWORD startadress, DWORD jumpadress, char* _file_name, char* jmpins)
{
	ofstream  writehand;
	writehand.open(_file_name, ios::in | ios::out | ios::binary);
	writehand.seekp(startadress, ios::beg);
	writehand.write(jmpins, 76);
	writehand.close();
}
void ELFToolHelp::SaveFile()
{
}
char * ELFToolHelp::d_value2jmpins(int d_value)
{
	
	char* a = (char*)malloc(sizeof(char) * 5);
	bitset<32> b1(d_value);
	b1 = b1 >> 2;
	bitset<24> b2;
	for (int i = 0; i < 24; i++)
	{
		b2.set(i, b1.operator[](i));
	}
	bitset<8> b3;

	for (int j = 0; j < 3; j++)
	{
		for (int k = 0; k < 8; k++)
		{
			b3.set(k, b2.operator[](k + j * 8));
		}
		a[j] = b3.to_ulong() & 0xff;


	}
	a[3] = 0xea;
	for (int i = 0; i < 4; i++)
	{
		cout << ((int)a[i] & 0xff) << endl;
	}
	return a;

}
