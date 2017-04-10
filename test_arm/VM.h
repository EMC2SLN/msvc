#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string>
#include <vector>
#include "arm.h"
#include "capstone.h"

using namespace std;

#define HANDLER_NUM  0x0b   //handler的数量
#define  OP1  37 //arm指令系统中用到的寄存器的数量,一共37个
#define  OP2  84  //操作码种类的个数

//////////////////////////////////////////////////////////////////////////

// 结构体成员变量共有四个
// 结构体功能：记录一条不可模拟指令需要用到的所有信息

typedef struct UnSimulate
{
	DWORD x86_inst_addr;	// 原x86指令的地址
	int x86_inst_length;  //原始X86指令的长度
	int newESI_offset;          //再次进入虚拟机ESI的指向，偏移地址
	DWORD parameter_offset;  //0x7D号Handler参数在ESI中的偏移
	int preVMDataID;   //为了生成UnSimulatable方便，添加的字段。
}UnSimulatable;

//////////////////////////////////////////////////////////////////////////
// 
// 生成pre——Vmdata中要用到的结构体
typedef struct Pre_VMData
{
	int Handler_id;	// Handler的序号
	int VI_id;	// 对应的虚拟指令结构的序号
	int NumberOfVMData;	// 所需VMData的个数
	DWORD parameter;	// 对应的Handler所需的VMData
	unsigned int index;		// 在VMData序列中的偏移

}PRE_VMDATA;

typedef struct VMDATA 
{
	int Handler_id;  //hLoad()调用,这部分之后详见common.cpp中的handler映射
	int	VI_id;
	DWORD  parameter;
	int NumberOfVMData;
	unsigned int index;
} VMDATA;




typedef struct VInstruction
{
	int operater; //操作码类型
	int addressing_mode;	//寻址方式
	DWORD operand;	//操作数
	DWORD org_inst_addr;	// 原指令的地址
	string vminstruction_str; //虚拟指令的字符形式
							  // reversed
}VI;
class VM
{
public:
	unsigned long m_sdkstart, m_sdkend;
	unsigned long m_VMContext[16];
	BYTE* m_VM_Data;
	unsigned long m_Handler_Addr[HANDLER_NUM];
	vector<VI> m_vi;
	vector<VMDATA> m_VMData;
	vector<PRE_VMDATA> m_preVMData;//用于存储preVMdata结构体的的容器
	int m_VMContext_order[15];//十五个寄存器
	int SetVI(cs_insn &key);
	int Judge(cs_insn key, int j, string s, cs_arm_op *op);
	string VIoperation(int a);
	string  DwordToString(DWORD number);
	DWORD GetPreVMDataParameter(DWORD operand);
	int SetPreVMData();
	DWORD size_VMInit;
	DWORD size_Dispatcher;
	DWORD size_Spring;
	DWORD size_VMData;//VMdata的大小
    vector<char> VMInit;
	vector<char> VMDispatcher;
	vector<char> Spring;
	void vector_handler_init();
	VM() {
		for (int i=0;i<sizeof(m_VMContext_order)/sizeof(m_VMContext_order[0]);i++)
		{
			m_VMContext_order[i] = i;
		}
		m_sdkstart = 0;
		m_sdkend = 0;
		memset(m_VMContext, 0, sizeof(DWORD) * 14);

		//memset(m_VM_Data, 0, VM_DATA_SIZE);
		memset(m_Handler_Addr, 0, sizeof(DWORD)*HANDLER_NUM);


		//给出了三个的大小
		size_VMInit = 0x3c;
		size_Dispatcher = 0x44;
		size_Spring = 0x4;
	};
	char* get_vmdata_start()
	{
		return vmData_start;
	}
	char * set_vmdata();
	void setsizeof_vmdata();
	DWORD getsizeof_vmdata() 
	{
		return size_VMData;
	}
	~VM() {
		delete m_VM_Data;
		free(VmData);
	
	};
private:

	char *vmData_start;//定位内存中vmdata的位置。
	char* VmData =NULL;
};