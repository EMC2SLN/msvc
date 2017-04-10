#include <platform.h>
#include <capstone.h>
#include "disassembly.h"
#include "common.h"
#include "VM.h"
#include <vector>
using namespace std;
extern   size_t handle;//����
#pragma region VM_GENERATE

//void print_insn_detail(cs_insn *ins)
//{
//	int i;
//
//	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
//	if (ins->detail == NULL)
//		return;
//	printf("ins->detail=%08x", ins->detail);
//	cs_arm *arm = &(ins->detail->arm);
//
//	if (arm->op_count)
//		printf("\top_count: %u\n", arm->op_count);
//
//	for (i = 0; i < arm->op_count; i++) {
//		cs_arm_op *op = &(arm->operands[i]);
//		switch ((int)op->type) {
//		default:
//			break;
//		case ARM_OP_REG:
//			printf("%d", op->reg);
//			printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
//			break;
//		case ARM_OP_IMM:
//			printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
//			break;
//		case ARM_OP_FP:
//#if defined(_KERNEL_MODE)
//			// Issue #681: Windows kernel does not support formatting float point
//			printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
//#else
//			printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
//#endif
//			break;
//		case ARM_OP_MEM:
//			printf("\t\toperands[%u].type: MEM\n", i);
//			if (op->mem.base != ARM_REG_INVALID)
//				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
//					i, cs_reg_name(handle, op->mem.base));
//			if (op->mem.index != ARM_REG_INVALID)
//				printf("\t\t\toperands[%u].mem.index: REG = %s\n",
//					i, cs_reg_name(handle, op->mem.index));
//			if (op->mem.scale != 1)
//				printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
//			if (op->mem.disp != 0)
//				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
//
//			break;
//		case ARM_OP_PIMM:
//			printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
//			break;
//		case ARM_OP_CIMM:
//			printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
//			break;
//		case ARM_OP_SETEND:
//			printf("\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE ? "be" : "le");
//			break;
//		case ARM_OP_SYSREG:
//			printf("\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
//			break;
//		}
//
//		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
//			if (op->shift.type < ARM_SFT_ASR_REG)
//				// shift with constant value
//				printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
//			else
//				// shift with register
//				printf("\t\t\tShift: %u = %s\n", op->shift.type,
//					cs_reg_name(handle, op->shift.value));
//		}
//
//		if (op->vector_index != -1) {
//			printf("\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
//		}
//
//		if (op->subtracted)
//			printf("\t\tSubtracted: True\n");
//	}
//
//	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
//		printf("\tCode condition: %u\n", arm->cc);
//
//	if (arm->update_flags)
//		printf("\tUpdate-flags: True\n");
//
//	if (arm->writeback)
//		printf("\tWrite-back: True\n");
//
//	if (arm->cps_mode)
//		printf("\tCPSI-mode: %u\n", arm->cps_mode);
//
//	if (arm->cps_flag)
//		printf("\tCPSI-flag: %u\n", arm->cps_flag);
//
//	if (arm->vector_data)
//		printf("\tVector-data: %u\n", arm->vector_data);
//
//	if (arm->vector_size)
//		printf("\tVector-size: %u\n", arm->vector_size);
//
//	if (arm->usermode)
//		printf("\tUser-mode: True\n");
//
//	if (arm->mem_barrier)
//		printf("\tMemory-barrier: %u\n", arm->mem_barrier);
//
//	printf("\n");
//}

int VM::SetVI(cs_insn &key)
{
	VI temper3;//��ʱ����,VI���͵�
	temper3.operater = 0x00;
	temper3.addressing_mode = 0x00;
	temper3.operand = 0;
	temper3.org_inst_addr = 0;
	temper3.vminstruction_str = "";//����ָ����ַ���ʽ
	cs_arm *csarm;
	
	csarm = &(key.detail->arm);
	printf("%d", csarm);
	for (int i = 1; i <csarm->op_count; i++) { //�Ժ����������������жϣ�ǰһ������
		cs_arm_op *cs_op = &(csarm->operands[i]);
		printf("op =%08x\n",cs_op);
		printf("%s\n", cs_reg_name(handle, cs_op->reg));
		printf("%08x\n",&key);

		Judge(key, 2, cs_reg_name(handle, cs_op->reg), cs_op);//cs_reg_name(handle, op->reg)Ϊ�Ĵ�����char*
	}
	//Ϊ�������������ָ��
	switch (key.id)
	{
	case 2:   //add��idΪ2
		temper3.operand = 0x03;

		break;
	}
	temper3.operater = 0x00000000;//����ָ���еĲ���������Ϊ0
	temper3.org_inst_addr = key.address;
	temper3.addressing_mode = 0x01;//�Ĵ���Ѱַ
	this->m_vi.push_back(temper3);
	cs_arm_op *cs_op = &(csarm->operands[0]);
	Judge(key, 4, cs_reg_name(handle, cs_op->reg), cs_op);//cs_reg_name(handle, op->reg)Ϊ�Ĵ�����char*
	return 0;
}

//jΪ����Ѱַ��ʽ��load ��store
int VM::Judge(cs_insn key, int j, string s, cs_arm_op *op)
{
	VI temper1;
	temper1.operater = 0x00;
	temper1.addressing_mode = 0x00;
	temper1.operand = 0;
	temper1.org_inst_addr = 0;

	if (s.compare("") == 0)
	{
		return 100;//���û�в��������򷵻�ֵΪ100
	}
	else
		if (j == 2)
		{
			int m = op->reg;
			temper1.operater = GetPreVMDataParameter(op->reg);
			temper1.addressing_mode = j;
			temper1.operand = j;	//load
			temper1.org_inst_addr = key.address;
		}
		else if (j ==4)//store
		{
			int m = op->reg;
			temper1.operater = GetPreVMDataParameter(op->reg);
			temper1.addressing_mode = j;
			temper1.operand = j;	//������Ϊstore
			temper1.org_inst_addr = key.address;
		}


	m_vi.push_back(temper1);
	return 0;
}
string VM::VIoperation(int a)//����ָ���࣬����Ϊ��������룬����Ϊ����ָ��� operater��Ӧ��id
{
	string str_operation;

	switch (a)
	{
	case 0x0:
		str_operation = "load";
		break;
	case 0x1:
		str_operation = "store";
		break;
	case 0x8:
		str_operation = "add";
		break;
	}
	return str_operation;
}
string VM::DwordToString(DWORD number)//DWord ����ת��string
{
	string temp;
	while (number != 0)
	{
		int a = number % 16;
		switch (a)
		{
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:  temp.insert(0, 1, a + 48);
			break;
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15: temp.insert(0, 1, a + 55);
		}
		//���Ҳ�ȡÿһλ��ֵ��������ת����ascii��ֵ�����뵽�ַ�����ǰ�� 
		number = number / 16; //����10ȡ����һλ 
	}
	return temp;
}
// �������ܣ����m_vi��operand��ʾһ���Ĵ���������m_vi��operand��m_VMContext_order����PreVMData��parameter
DWORD VM::GetPreVMDataParameter(DWORD operand)//�õ��Ĵ�����VMContext�е�λ��, ����ֵ��PreVMData��parameter
{
	switch (operand)
	{
		//0x01-0x04 �ֱ����al.ah.ax.eax,���Ƕ���ͬһ��������ʾ
	case 66://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[0];
		break;
	}
	case 67://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[1];
		break;
	}
	case 68://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[2];
		break;
	}
	case 69://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[3];
		break;
	}
	case 70://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[4];
		break;
	}
	case 71://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[5];
		break;
	}
	case 72://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[6];
		break;
	}
	case 73://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[7];
		break;
	}
	case 74://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[8];
		break;
	}
	case 75://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[9];
		break;
	}
	case 76://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[10];
		break;
	}
	case 77://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[11];
		break;
	}
	case 78://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[12];
		break;
	}
	case 79://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[13];
		break;
	}
	case 80://capstone�д�66��ʼ��ţ���66����Ĵ���r0;
	{
		return this->m_VMContext_order[14];
		break;
	}
	default:
	{
		cout << "GetPreVMDataParameter unresolved" << endl;
		return 0xFFFFFFFF;
	}
	}
}
int VM::SetPreVMData()
{
	PRE_VMDATA tempPreVMData;
	UnSimulatable tempUnSimulatable;
	cout << m_vi.size() << endl;
	for (int i = 0; i < this->m_vi.size(); i++)
	{
		switch (this->m_vi[i].operand)//����ö�ٵ�id���ж�Ѱַ��ʽ 
		{
		case 0x02://�����������load�Ĵ���
		{
			cout << "LOAD" << endl;
			tempPreVMData.Handler_id = 2;
			tempPreVMData.VI_id = 2;
			tempPreVMData.parameter = this->m_vi[i].operater;
			tempPreVMData.NumberOfVMData = 2;
			tempPreVMData.index = 0;
			this->m_preVMData.push_back(tempPreVMData);
			break;
		}
		case 0x04://�����������store�ĵĴ���
		{
			    cout << "STROE" << endl;
				tempPreVMData.Handler_id = 0x04;
				tempPreVMData.VI_id = i;
				tempPreVMData.parameter = this->m_vi[i].operater;
				tempPreVMData.NumberOfVMData = 2;
				tempPreVMData.index = 0;
				this->m_preVMData.push_back(tempPreVMData);
				break;
			}
		case 0x03://addָ��
		{
			tempPreVMData.Handler_id = 0x03;
			tempPreVMData.VI_id = i;
			tempPreVMData.parameter = 0xFFFFFFFF;
			tempPreVMData.NumberOfVMData = 1;
			tempPreVMData.index = 0;
			this->m_preVMData.push_back(tempPreVMData);
			break;
		}
		default:
		{
			cout << "ADD unresolved!" << endl;
			break;

		}
		}
		
	}
	for (int i = 0; i < m_preVMData.size(); i++)
	{
		if (m_preVMData[i].NumberOfVMData == 1)
		{
			cout << m_preVMData[i].Handler_id;
		}
		else
		{
			cout << m_preVMData[i].Handler_id << "   " << m_preVMData[i].parameter << endl;
		}
	}
	setsizeof_vmdata();
	set_vmdata();
	return 0;
}
char* VM::set_vmdata()
{  
	VmData =(char*)malloc(getsizeof_vmdata() * sizeof(char));
	UINT ioffset = 0;
	char a[12] = { 0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };
	memcpy(&VmData[ioffset], a, sizeof(a));
	ioffset += sizeof(a);
	//char *p = VmData;
	//char *q =a ;
	//while (*q)
	//{
	//	*p++ = *q++;//��str2������ַ���str1β�����ӵ�str1��
	//}
	
	
	for (int i = 0; i < m_preVMData.size(); i++)
	{
		if (m_preVMData[i].NumberOfVMData == 1)
		{
			VmData[ioffset]=(char)m_preVMData[i].Handler_id;
			ioffset += 1;
		}
		else
		{
			VmData[ioffset] = (char)m_preVMData[i].Handler_id;
			ioffset += 1;
			VmData[ioffset] = (char)m_preVMData[i].parameter;
			ioffset += 1;
		}
	}
	VmData[ioffset] = 0xa;
	ioffset += 1;
	vmData_start = VmData;
	return vmData_start;

}
void VM::setsizeof_vmdata()
{

	for (int i = 0; i < m_preVMData.size(); i++)
	{
		size_VMData += m_preVMData[i].NumberOfVMData;
	}
	size_VMData = 13 + size_VMData;//13�Ǹ���handler�Ĵ�С
}

#pragma  endregion



#pragma  region HANDLER
//ȷ��ele_VMInit[] =60��ele_VMDispatcher=68
char ele_VMInit[] = { 0xFF,0xC0,0x2D,0xE9,0x07,0x70,0x47,0xE0,0x95,0x7E,0x8F,0xE2,0x95,0x7E,0x8F,0xE2,0x95,0x7E,0x8F,0xE2,0x95,0x7E,0x8F,0xE2,0xA1,0x7E,0x8F,0xE2,0x06,0x60,0x46,0xE0,0x1B,0x6E,0x4F,0xE2
,0x00,0xF0 ,0x20,0xE3 ,0x00,0xF0 ,0x20,0xE3 ,0x00,0xF0 ,0x20,0xE3 ,0x00,0xF0 ,0x20,0xE3 ,0x00,0xF0 ,0x20,0xE3 ,0x00,0xF0 ,0x20,0xE3 };
//char ele_VMInit[] = { 0xFF, 0xC0, 0x2D, 0xE9, 0x07, 0x70, 0x47, 0xE0,  0x15, 0x7E, 0x8F, 0xE2, 0x06, 0x60, 0x46, 0xE0, 0xA4, 0x60, 0x4F, 0xE2,
//0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3
//,0x00,0xF0 ,0x20,0xE3  };
char ele_VMDispatcher[] = { 0x00,0x00 ,0xD7 ,0xE5 ,0x06 ,0x50 ,0xA0 ,0xE1  ,0x40 ,0x50 ,0x85 ,0xE2 ,0x00 ,0x51 ,0x85 ,0xE0 ,0x01 ,0x70 ,0x87 ,0xE2 ,0x00 ,0x50 ,0x95 ,0xE5  ,0x0F ,0x50 ,0x85 ,0xE0 ,0x35 ,0xFF ,0x2F ,0xE1,
0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3,0x00,0xF0 ,0x20,0xE3
 };
char ele_spring[] = {/* 0x04, 0x00, 0x9F, 0xE5, 0x01, 0x00, 0x2D, 0xE9,*/ 0x00, 0x00, 0xA0, 0xE1 };
void VM::vector_handler_init()
{
	
	for (int i = 0; i < sizeof(ele_VMInit); i++)
	{
		VMInit.push_back(ele_VMInit[i]);
	}
	for (int i = 0; i < sizeof(ele_VMDispatcher); i++)
	{
		VMDispatcher.push_back(ele_VMDispatcher[i]);
	}
	for (int i = 0; i < sizeof(ele_spring); i++)
	{
		Spring.push_back(ele_spring[i]);
	}
}


#pragma  endregion