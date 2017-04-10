#pragma once
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <platform.h>
#include <capstone.h>
#define     MAX_INSTRUCTION_NUM  10000  //要反汇编的指令有多少条

class Disassembly
{
public:
	cs_arm *arm;
	cs_arm_op *op;
	size_t count;
	cs_insn *insn;
	struct platform {
		cs_arch arch;
		cs_mode mode;
		unsigned char *code;
		size_t size;
		char *comment;
		int syntax;
	};
	Disassembly() 
	{
		Final_Keyresults = (Pcs_insn)malloc(sizeof(Pcs_insn)* MAX_INSTRUCTION_NUM);
	}

	void print_insn_detail(cs_insn *ins);
	void print_string_hex(char *comment, unsigned char *str, size_t len);
	int Get_NumofInstructions();
	void DisamAllInstr();
	void Set_Fkeyresults(cs_insn  keyresults, int i);
	Pcs_insn  Get_Fkeyresults();
	~Disassembly()
	{
		cs_free(insn, count);
		free(this->Final_Keyresults);
		handleclose();
	};
	void handleclose();
protected:
private:
	Pcs_insn Final_Keyresults;
};
