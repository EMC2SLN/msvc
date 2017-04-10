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
#define	HANDLER_SIZE 150*20*4 //150��handler��ƽ��ÿ��20��ָ�ÿ��ָ��4�ֽڡ�
#define VMDATA_SIZE 300

//extern cs_insn *insn;
using namespace std;

unsigned char* STR;
int length;
int main(int argc, char* argv[]) {
	/************************************************************************/
	/*��Ҫ����ģ���*/
	/************************************************************************/

	char *_start_adress = NULL;
	char *_end_adress = NULL;
	char * _file_name = "C:\\Users\\MarissaSelina\\Desktop\\nisl.so";
	/************************************************************************/
	/*��Ҫ����������*/
	/************************************************************************/
	DWORD addr_VM_CONTEXT;
	DWORD addr_VMInit;
	DWORD addr_Handlers;
	DWORD addr_VM_DATA;
	DWORD addr_VMspring;
	DWORD  addr_VMDispatcher;
	DWORD addr_VM_hand_Address_list;
	bool flagSDK = 0;//ֱ�����뷽ʽΪ0�����ұ�ǩ�ķ�ʽΪ1;
	DWORD _new_section_size = 0;
	char *_new_section;
	UINT iOffSet = 0;
	int jmpadress;
	int jmp2org;
	/************************************************************************/
	/*��Ҫ��ĳ�ʼ����*/
	/************************************************************************/
	VM *vm = NULL;
	vm = new VM();
	HandlerMaster *handlermaster = new HandlerMaster();
	ELFToolHelp  *Ehelp = NULL;
	Ehelp = new ELFToolHelp();
	Disassembly *Disasmsresults = new Disassembly();
	/************************************************************************/
	/* ��Ҫ������                                                           */
	/************************************************************************/
	Ehelp->file_handle.open(_file_name, ios::in | ios::out | ios::binary);
	if (Ehelp->file_handle.is_open()) {
		Ehelp->read_elf_header();

		if (!Ehelp->is_ELF()) {
			cout << "��ELF��ʽ" << endl;
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
		STR = Ehelp->SearchSDK(vm->m_sdkstart, vm->m_sdkend,length);//searchSKD,������ֵ��
		Ehelp->file_handle.close();
		vm->vector_handler_init();
		Disasmsresults->DisamAllInstr();
		// ��������ָ��
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
	addr_VMInit = addr_VM_CONTEXT + sizeof(vm->m_VMContext) + sizeof(DWORD)*(TOL_HANDLER_NUM);//init֮�ϴ�handler�ĵ�ַ��һ��handlerռ���ĸ��ֽ�
	addr_VMDispatcher = addr_VMInit+vm->size_VMInit;
	addr_Handlers = addr_VMInit + vm->size_VMInit + vm->size_Dispatcher;//size_VMInit��size_dispatcher��VM���캯��ʱ�Ѿ���������Ӧ�ĳ�ʼֵ
	addr_VM_DATA = addr_Handlers + (HANDLER_SIZE );
	addr_VMspring = addr_VM_DATA + VMDATA_SIZE;
	//������������ת���ַ������
	memset(vm->m_Handler_Addr, 0x00, sizeof(vm->m_Handler_Addr));//handler����ʼ��ַ����ʼ���ڴ�ռ䣬ȫ������Ϊ00
	for (int ih = 0; ih < HANDLER_NUM; ih++)
	{
		vm->m_Handler_Addr[ih] = handlermaster->GetEach_handler_offset()[ih] + addr_Handlers - (addr_VMDispatcher+28+4);//��ֵ��ӦΪÿ��handler����handler�洢���е���ʵ��ַ,+28�ҵ���תָ���λ�ã���4�ҵ�pc��λ��
		printf("%08x  ", vm->m_Handler_Addr[ih]);
	}
	_new_section = new char[_new_section_size];
	char* jmp2VM_ins = new char(5);
	//�޸�VM_START���������
	if (flagSDK)
	{
		jmpadress = addr_VMspring - vm->m_sdkstart - 8;
		memset(jmp2VM_ins, 0x00, 4);
		memcpy(jmp2VM_ins, Ehelp->d_value2jmpins(jmpadress), 4);
	}
	else
	{
		//������flafSKDΪ�յ����
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
		if (iCounter == HANDLER_NUM - 1)//���һ��handler����Դ��ַ
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
		// ÿ��Handler�������һ��Jmp����Dispatcher
		

	}

	/******************************************�����е�handler��������Ӧλ��*******************************/
	memcpy(&_new_section[iOffSet], handlermaster->GetHeap_start(), handlermaster->GetHeap_size());
	iOffSet +=( HANDLER_SIZE);
	printf("ioffest = %08x", iOffSet);
	memcpy(&_new_section[iOffSet], vm->get_vmdata_start(), vm->getsizeof_vmdata());
	iOffSet += VMDATA_SIZE;
	memcpy(&_new_section[iOffSet], (char*)&(vm->Spring[0]), vm->size_Spring);
	iOffSet += vm->size_Spring;
	printf("adress =%08x", addr_VM_DATA);
	//// �޸�spring�� jmpָ�� VMInit�ĵ�ַ
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

