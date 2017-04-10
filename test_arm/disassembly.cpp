#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "elf.h"
#include "ELFToolHelp.h"
#include <platform.h>
#include <capstone.h>
#include "disassembly.h"
#include"sys_eny.h"
using namespace std;


size_t handle;
extern unsigned char* STR;
extern int length;
 void Disassembly:: print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

 void Disassembly::print_insn_detail(cs_insn *ins)
{
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;
	printf("ins->detail=%08x", ins->detail);
	arm = &(ins->detail->arm);

	if (arm->op_count)
		printf("\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		op = &(arm->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ARM_OP_REG:
			printf("\t\toperands[%u].type: REG = %s,op->reg =%d\n", i, cs_reg_name(handle, op->reg), op->reg);
			break;
		case ARM_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
			break;
		case ARM_OP_FP:
#if defined(_KERNEL_MODE)
			// Issue #681: Windows kernel does not support formatting float point
			printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
			printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
			break;
		case ARM_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != ARM_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
					i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != ARM_REG_INVALID)
				printf("\t\t\toperands[%u].mem.index: REG = %s\n",
					i, cs_reg_name(handle, op->mem.index));
			if (op->mem.scale != 1)
				printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

			break;
		case ARM_OP_PIMM:
			printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
			break;
		case ARM_OP_CIMM:
			printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
			break;
		case ARM_OP_SETEND:
			printf("\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE ? "be" : "le");
			break;
		case ARM_OP_SYSREG:
			printf("\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
			break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				// shift with constant value
				printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			else
				// shift with register
				printf("\t\t\tShift: %u = %s\n", op->shift.type,
					cs_reg_name(handle, op->shift.value));
		}

		if (op->vector_index != -1) {
			printf("\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
		}

		if (op->subtracted)
			printf("\t\tSubtracted: True\n");
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		printf("\tCode condition: %u\n", arm->cc);

	if (arm->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm->writeback)
		printf("\tWrite-back: True\n");

	if (arm->cps_mode)
		printf("\tCPSI-mode: %u\n", arm->cps_mode);

	if (arm->cps_flag)
		printf("\tCPSI-flag: %u\n", arm->cps_flag);

	if (arm->vector_data)
		printf("\tVector-data: %u\n", arm->vector_data);

	if (arm->vector_size)
		printf("\tVector-size: %u\n", arm->vector_size);

	if (arm->usermode)
		printf("\tUser-mode: True\n");

	if (arm->mem_barrier)
		printf("\tMemory-barrier: %u\n", arm->mem_barrier);

	printf("\n");
}

 void Disassembly::DisamAllInstr()
{
	struct platform platforms[] = {
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char *)STR,
			length,
			"ARM"
		},	
	};

	uint64_t address = 0x80001000;
	
	int i;
	for (i = 0; i < sizeof(platforms) / sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		if (platforms[i].syntax)
			cs_option(handle, CS_OPT_SYNTAX, platforms[i].syntax);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\t%d\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, insn[j].id);
				print_insn_detail(&insn[j]);
				printf("ins->detail =%08x",insn[i].detail);
				this->Set_Fkeyresults(insn[j], j);
				cs_arm *arm;
				arm = &(insn[j].detail->arm);
				printf("%d", arm);
				for (int i = arm->op_count; i > 1; i--) { //对后面两个操作数做判断，前一个保留
					cs_arm_op *op = &(arm->operands[i]);
					printf("op =%08x", op);
				}
			}
			printf("0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);
		}
		else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		
	}
}
 int Disassembly::Get_NumofInstructions()
 {
	 return count;
 }
 Pcs_insn Disassembly::Get_Fkeyresults()
 {
	 return this->Final_Keyresults;
 }
 void Disassembly::handleclose()
 {
	 cs_close(&handle);
 }
 void Disassembly::Set_Fkeyresults(cs_insn  keyresults,int i) 
 {
	 this->Final_Keyresults[i] = keyresults;
	 printf("this->Final_Keyresults[i].address =%llx", this->Final_Keyresults[i].address);
	 printf("this->Final_Keyresults[i].detail =%08x", this->Final_Keyresults[i].detail);
 }


