

#ifndef COMMON_H_FILE
#define COMMON_H_FILE

#include<windows.h>
#include <vector>
#include "VM.h"
using namespace std;


#define SDKSIZE 28//起始和结束SKD的大小都是28字节
// 定义handler起始地址和大小的结构体  20140729-LGH

//extern HandlersInfo handlers[];
BYTE* switchEndian(DWORD _rva);
typedef struct
{
	char* addr;
	DWORD size;
}HandlersInfo;
class Common
{
public:
	vector<char> h000;
	vector<char> h001;
	vector<char> h002;
	vector<char> h003;
	vector<char> h004;
	vector<char> h075;
	vector<char> h007;
	vector<char> h005;
	vector<char> h074;
	vector<char> h00A;
	vector<char> h012;
	void handler_init();
	HandlersInfo *handlers;
	Common() {
		handlers = (HandlersInfo*)malloc(sizeof(HandlersInfo)*HANDLER_NUM);
		//DWORD handlers[15] = { 0xc,0x4, 0x10, 0xc, 0x10, 0x4, 0x4, 0xc, 0x8, 0x4, 0x8 };
	}
protected:
private:
};

//Common *com = new Common();
class  HandlerMaster
{
private:
	Common *com=new Common();
public:
	HandlerMaster()
	{
		
		DWORD * offsetofhandler;
		int * addrofjmp;
		addrofjmp = (int*)calloc(HANDLER_NUM, sizeof(int));
		offsetofhandler = (DWORD *)calloc(HANDLER_NUM, sizeof(DWORD));
	    com->handler_init();
		this->SetEach_handler_offset(offsetofhandler);
		this->SetHeap_start(NULL);
		this->SetHeap_size(0);
		this->SetEach_jmp_offset(addrofjmp);
	}
	DWORD * GetEach_handler_offset()
	{
		return this->Each_handler_offset;
	};

	void SetEach_handler_offset(DWORD * mallocaddr)
	{
		for (int i = 0; i < HANDLER_NUM; i++)
		{
			if (i == 0)
			{
				mallocaddr[i] = 0;
			}
			else
			{
				DWORD offest = 0;
				for (int j = 0; j < i; j++)
				{
					offest = offest +com-> handlers[j].size;
				}
				mallocaddr[i] = offest;
			}

		}
		this->Each_handler_offset = mallocaddr;
	};
	void setsizeof_handler(DWORD size)
	{
		
		
		size_Handlers = size;
	}
	DWORD getsizeof_handler()
	{
		this->Heap_size = 0;
		for (int i = 0; i < HANDLER_NUM; i++)
		{
			this->Heap_size += com->handlers[i].size;
		}
		return this->Heap_size;
	}




	void SetHeap_start(char* mallocaddr)
	{
		Heap_handler = (char*)malloc(getsizeof_handler() * sizeof(char*));
		Heap_size = getsizeof_handler() * sizeof(char*);
		memset(Heap_handler, 0x00, Heap_size);
		UINT iOffSet = 0;
		for (int i=0;i<HANDLER_NUM;i++)
		{
			memcpy(&Heap_handler[iOffSet], com->handlers[i].addr, com->handlers[i].size);
			iOffSet = iOffSet + com->handlers[i].size;
		}
		this->Heap_start = Heap_handler;
		printf("heap_start =%08x", Heap_handler);
	};
	char* GetHeap_start()
	{   
		return this->Heap_start;
	};




	void SetHeap_size(DWORD size)
	{
		this->Heap_size = 0;
		for (int i = 0; i < HANDLER_NUM; i++)
		{
			this->Heap_size += com->handlers[i].size;
		}
		
	};
	DWORD GetHeap_size()
	{
		return this->Heap_size;
	};
	int * GetEach_jmp_offset()
	{
		return this->Each_jmp_offset;
	};
	void SetEach_jmp_offset(int * mallocaddr)
	{
		for (int i =  0; i < HANDLER_NUM; i++)
		{
			   ////////////////////////////
				DWORD offest = 0;
				for (int j = 0; j <= i; j++)
				{
					offest = offest + com->handlers[j].size;
				}
				mallocaddr[i] = offest-4;
			

		}
		this->Each_jmp_offset = mallocaddr;
	};

protected:
	DWORD* Each_handler_offset; //每个handler起始地址相对于堆上起始地址的偏移量
private:
	DWORD size_Handlers;
	char*  Heap_start;//重定位到新的堆空间的起始地址
	DWORD  Heap_size;
	unsigned short h_index;                 //handler的索引*/
	char* Heap_handler =NULL;
	int * Each_jmp_offset;
};

#endif
