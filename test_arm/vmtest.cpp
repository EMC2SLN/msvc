#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <windows.h>
#include "elf.h"
#include "ELFToolHelp.h"
#include <assert.h>
#include "disassembly.h"
#include "common.h"
#include "VM.h"

#define TOL_HANDLER_NUM   150
#define	HANDLER_SIZE 150*20*4 //150个handler，平均每条20条指令，每条指令4字节。
#define VMDATA_SIZE 300

//extern cs_insn *insn;
using namespace std;

unsigned char* STR;
int length;
int main(int argc, char* argv[]) {
	/************************************************************************/
	/*重要变量模拟段*/
	/************************************************************************/

	char *_start_adress = NULL;
	char *_end_adress = NULL;
	char * _file_name = "C:\\Users\\lz\\Desktop\\libnat.so";
	/************************************************************************/
	/*重要变量声明段*/
	/************************************************************************/
	DWORD addr_VM_CONTEXT;
	DWORD addr_VMInit;
	DWORD addr_Handlers;
	DWORD addr_VM_DATA;
	DWORD addr_VMspring;
	DWORD  addr_VMDispatcher;
	DWORD addr_VM_hand_Address_list;
	bool flagSDK = 0;//直接输入方式为0，查找标签的方式为1;
	DWORD _new_section_size = 0;
	char *_new_section;
	UINT iOffSet = 0;
	int jmpadress;
	int jmp2org;
	/************************************************************************/
	/*重要类的初始化段*/
	/************************************************************************/
	VM *vm = NULL;
	vm = new VM();
	HandlerMaster *handlermaster = new HandlerMaster();
	ELFToolHelp  *Ehelp = NULL;
	Ehelp = new ELFToolHelp();
	Disassembly *Disasmsresults = new Disassembly();
	/************************************************************************/
	/* 重要操作段                                                           */
	/************************************************************************/
	Ehelp->file_handle.open(_file_name, ios::in | ios::out | ios::binary);
	if (Ehelp->file_handle.is_open()) {
		Ehelp->read_elf_header();

		if (!Ehelp->is_ELF()) {
			cout << "非ELF格式" << endl;
		}
		Ehelp->init();
		Ehelp->print_elf_header();
		Ehelp->read_program_headers();
		Ehelp->print_program_headers();
		Ehelp->read_section_headers();
		Ehelp->print_section_headers();
		Ehelp->print_symbols();




	}
	else
	{
		cout << "the filepath is not exist!";

	}
	if (_start_adress != NULL&&_end_adress != NULL)
	{
		flagSDK = 0;
		//vm->m_sdkstart = string_to_hex(_start_adress);
		//vm->m_sdkend = string_to_hex(_end_adress);

	}
	else
	{
		flagSDK = 1;
		STR = Ehelp->SearchSDK(vm->m_sdkstart, vm->m_sdkend,length);//searchSKD,并返回值。
		Ehelp->file_handle.close();
		vm->vector_handler_init();
		Disasmsresults->DisamAllInstr();
		// 生成虚拟指令
		printf("Disasmsresults->Get_NumofInstructions() =%d", Disasmsresults->Get_NumofInstructions());
	for (int i = 0; i < Disasmsresults->Get_NumofInstructions(); i++)
		{
			printf("%08x", Disasmsresults->insn[i].detail);
			printf("Disasmsresults->Get_Fkeyresults()[i] =%08x", &(Disasmsresults->Get_Fkeyresults()[i]));
			vm->SetVI(Disasmsresults->Get_Fkeyresults()[i]);

			
		}
	   vm->SetPreVMData();
	
	}
	printf("%08x", Ehelp->getaddresofnewsection(_file_name, _new_section_size));
	_new_section_size = sizeof(vm->m_VMContext) + sizeof(char*)*(TOL_HANDLER_NUM) + vm->size_VMInit + vm->size_Dispatcher + (HANDLER_SIZE ) + VMDATA_SIZE + vm->size_Spring;
	//_new_section_size = 8;
	addr_VM_CONTEXT = Ehelp->getaddresofnewsection(_file_name, _new_section_size);
	addr_VM_hand_Address_list = addr_VM_CONTEXT + sizeof(vm->m_VMContext);
	addr_VMInit = addr_VM_CONTEXT + sizeof(vm->m_VMContext) + sizeof(DWORD)*(TOL_HANDLER_NUM);//init之上存handler的地址表，一个handler占用四个字节
	addr_VMDispatcher = addr_VMInit+vm->size_VMInit;
	addr_Handlers = addr_VMInit + vm->size_VMInit + vm->size_Dispatcher;//size_VMInit和size_dispatcher在VM构造函数时已经给出了相应的初始值
	addr_VM_DATA = addr_Handlers + (HANDLER_SIZE );
	addr_VMspring = addr_VM_DATA + VMDATA_SIZE;
	//接下来处理跳转表地址的问题
	memset(vm->m_Handler_Addr, 0x00, sizeof(vm->m_Handler_Addr));//handler的起始地址表，初始化内存空间，全部设置为00
	for (int ih = 0; ih < HANDLER_NUM; ih++)
	{
		vm->m_Handler_Addr[ih] = handlermaster->GetEach_handler_offset()[ih] + addr_Handlers - (addr_VMDispatcher+28+4);//其值对应为每个handler的在handler存储块中的真实地址,+28找到跳转指令的位置，加4找到pc的位置
		printf("%08x  ", vm->m_Handler_Addr[ih]);
	}
	_new_section = new char[_new_section_size];
	char* jmp2VM_ins = new char(5);
	//修改VM_START跳入虚拟机
	if (flagSDK)
	{
		jmpadress = addr_VMspring - vm->m_sdkstart - 8;
		memset(jmp2VM_ins, 0x00, 4);
		memcpy(jmp2VM_ins, Ehelp->d_value2jmpins(jmpadress), 4);
	}
	else
	{
		//不处理flafSKD为空的情况
	}

	
	memset(_new_section, 0x00, _new_section_size);
	iOffSet = 0;
	memcpy(&_new_section[iOffSet], vm->m_VMContext, sizeof(vm->m_VMContext));
	iOffSet += sizeof(vm->m_VMContext);
	memcpy(&_new_section[iOffSet], vm->m_Handler_Addr, sizeof(DWORD)*HANDLER_NUM);
	iOffSet += sizeof(DWORD)*(TOL_HANDLER_NUM);
	printf("iOffSet=%08x", iOffSet);
	printf("adressofhandler=%08x", addr_VMInit);
	memcpy(&_new_section[iOffSet], (char*)&(vm->VMInit[0]), vm->size_VMInit);
	iOffSet += vm->size_VMInit;
	memcpy(&_new_section[iOffSet], (char*)&(vm->VMDispatcher[0]), vm->size_Dispatcher);
	iOffSet += vm->size_Dispatcher;
	printf("iOffSet=%08x", iOffSet);
	printf("adressofhandler=%08x", addr_Handlers);
	for (int iCounter = 0; iCounter < HANDLER_NUM; iCounter++)
	{
		if (iCounter == HANDLER_NUM - 1)//最后一条handler跳回源地址
		{
			int source_addr = addr_Handlers + (handlermaster->GetEach_jmp_offset()[iCounter]);
			int  jmp2org = (vm->m_sdkend + 1 + 28) - source_addr - 8;
			char* B_2_dispa_ins = Ehelp->d_value2jmpins(jmp2org);
			memset(handlermaster->GetHeap_start() + (handlermaster->GetEach_jmp_offset()[iCounter]), 0x00, 4);
			memcpy(handlermaster->GetHeap_start() + (handlermaster->GetEach_jmp_offset()[iCounter]), B_2_dispa_ins, 4);
		}
		else {
			int source_addr = addr_Handlers + (handlermaster->GetEach_jmp_offset()[iCounter]);
			int  B_2_dispa_ddr = addr_VMDispatcher - source_addr - 8;
			printf("vmdispatcher = %08x", addr_VMDispatcher);
			printf("source_addr =%08x", source_addr);
			printf("B_2_dispa_ddr =%08x\n", B_2_dispa_ddr);
			char* B_2_dispa_ins = Ehelp->d_value2jmpins(B_2_dispa_ddr);
			memset(handlermaster->GetHeap_start() + (handlermaster->GetEach_jmp_offset()[iCounter]), 0x00, 4);
			memcpy(handlermaster->GetHeap_start() + (handlermaster->GetEach_jmp_offset()[iCounter]), B_2_dispa_ins, 4);
		}
		// 每个Handler后面添加一个Jmp跳回Dispatcher
		

	}

	/******************************************将所有的handler拷贝到对应位置*******************************/
	memcpy(&_new_section[iOffSet], handlermaster->GetHeap_start(), handlermaster->GetHeap_size());
	iOffSet +=( HANDLER_SIZE);
	printf("ioffest = %08x", iOffSet);
	memcpy(&_new_section[iOffSet], vm->get_vmdata_start(), vm->getsizeof_vmdata());
	iOffSet += VMDATA_SIZE;
	memcpy(&_new_section[iOffSet], (char*)&(vm->Spring[0]), vm->size_Spring);
	iOffSet += vm->size_Spring;
	printf("adress =%08x", addr_VM_DATA);
	//// 修改spring中 jmp指令 VMInit的地址
	//char cha_spring04[] = { 0x04, 0x00, 0x9F, 0xE5 };
	//memcpy(&_new_section[iOffSet-12], cha_spring04, 4);
	//memcpy(&_new_section[iOffSet - 4], Ehelp->d_value2jmpins(addr_VMInit - (addr_VMspring+8)-8), sizeof(char) * 4);
	memcpy(&_new_section[iOffSet - 4], Ehelp->d_value2jmpins(addr_VMInit - (addr_VMspring ) - 8), sizeof(char) * 4);
	printf("offest =%d\n", iOffSet);
	printf("_new_section_size%d", _new_section_size);
	Ehelp->setnewsename();
	printf("add new section \n%08x\n", _new_section);
	printf("\n%08x\n", _new_section_size);
	
	Ehelp->AddCodeSection(_new_section, _new_section_size, _file_name);
	
	Ehelp->startSDKreduce(vm->m_sdkstart, jmpadress, _file_name, jmp2VM_ins);
	delete _new_section;
	delete Ehelp;
	delete vm;
	delete handlermaster;
	delete Disasmsresults;
	system("pause");
	return 0;
}

