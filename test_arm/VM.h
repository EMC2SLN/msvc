#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string>
#include <vector>
#include "arm.h"
#include "capstone.h"

using namespace std;

#define HANDLER_NUM  0x0b   //handler������
#define  OP1  37 //armָ��ϵͳ���õ��ļĴ���������,һ��37��
#define  OP2  84  //����������ĸ���

//////////////////////////////////////////////////////////////////////////

// �ṹ���Ա���������ĸ�
// �ṹ�幦�ܣ���¼һ������ģ��ָ����Ҫ�õ���������Ϣ

typedef struct UnSimulate
{
	DWORD x86_inst_addr;	// ԭx86ָ��ĵ�ַ
	int x86_inst_length;  //ԭʼX86ָ��ĳ���
	int newESI_offset;          //�ٴν��������ESI��ָ��ƫ�Ƶ�ַ
	DWORD parameter_offset;  //0x7D��Handler������ESI�е�ƫ��
	int preVMDataID;   //Ϊ������UnSimulatable���㣬��ӵ��ֶΡ�
}UnSimulatable;

//////////////////////////////////////////////////////////////////////////
// 
// ����pre����Vmdata��Ҫ�õ��Ľṹ��
typedef struct Pre_VMData
{
	int Handler_id;	// Handler�����
	int VI_id;	// ��Ӧ������ָ��ṹ�����
	int NumberOfVMData;	// ����VMData�ĸ���
	DWORD parameter;	// ��Ӧ��Handler�����VMData
	unsigned int index;		// ��VMData�����е�ƫ��

}PRE_VMDATA;

typedef struct VMDATA 
{
	int Handler_id;  //hLoad()����,�ⲿ��֮�����common.cpp�е�handlerӳ��
	int	VI_id;
	DWORD  parameter;
	int NumberOfVMData;
	unsigned int index;
} VMDATA;




typedef struct VInstruction
{
	int operater; //����������
	int addressing_mode;	//Ѱַ��ʽ
	DWORD operand;	//������
	DWORD org_inst_addr;	// ԭָ��ĵ�ַ
	string vminstruction_str; //����ָ����ַ���ʽ
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
	vector<PRE_VMDATA> m_preVMData;//���ڴ洢preVMdata�ṹ��ĵ�����
	int m_VMContext_order[15];//ʮ����Ĵ���
	int SetVI(cs_insn &key);
	int Judge(cs_insn key, int j, string s, cs_arm_op *op);
	string VIoperation(int a);
	string  DwordToString(DWORD number);
	DWORD GetPreVMDataParameter(DWORD operand);
	int SetPreVMData();
	DWORD size_VMInit;
	DWORD size_Dispatcher;
	DWORD size_Spring;
	DWORD size_VMData;//VMdata�Ĵ�С
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


		//�����������Ĵ�С
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

	char *vmData_start;//��λ�ڴ���vmdata��λ�á�
	char* VmData =NULL;
};