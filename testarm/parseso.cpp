/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <platform.h>
#include <capstone.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
	int syntax;
};

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static void print_insn_detail(cs_insn *ins)
{
	cs_arm *arm;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm = &(ins->detail->arm);

	if (arm->op_count)
		printf("\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ARM_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
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

static void test()
{

#define ARM_CODE "\x01\x00\x80\xe0"
#define ARM_CODE2 "\x01\x00\x80\xe0"
#define THUMB_CODE "\x01\x00\x80\xe0"
#define THUMB_CODE2 "\x01\x00\x80\xe0"
#define THUMB_MCLASS "\x01\x00\x80\xe0"
#define ARMV8 "\x01\x00\x80\xe0"

	struct platform platforms[] = {
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char *)ARM_CODE,
			sizeof(ARM_CODE) - 1,
			"ARM"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE,
			sizeof(THUMB_CODE) - 1,
			"Thumb"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)ARM_CODE2,
			sizeof(ARM_CODE2) - 1,
			"Thumb-mixed"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE2,
			sizeof(THUMB_CODE2) - 1,
			"Thumb-2 & register named with numbers",
			CS_OPT_SYNTAX_NOREGNAME
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
			(unsigned char*)THUMB_MCLASS,
			sizeof(THUMB_MCLASS) - 1,
			"Thumb-MClass"
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_ARM + CS_MODE_V8),
			(unsigned char*)ARMV8,
			sizeof(ARMV8) - 1,
			"Arm-V8"
		},
	};

	uint64_t address = 0x80001000;
	cs_insn *insn;
	int i;
	size_t count;

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
			}
			printf("0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		}
		else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();
	system("pause");

	return 0;
}

