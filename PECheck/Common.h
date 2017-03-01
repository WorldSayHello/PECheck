#pragma once
#include "stdafx.h"
#include "afxdialogex.h"
#include <list>
#include <string>
#include <stdio.h>

#define WM_START_PARSE_PE WM_USER+100 //开始解析PE
#define WM_END_PARSE_PE   WM_USER+101 //结束解析PE

#define _offset(s,m) ((UINT32)&(((s*)0)->m))

const UINT16 NT_OPTIONAL_32_MAGIC = 0x10B; //32位程序
const UINT16 NT_OPTIONAL_64_MAGIC = 0x20B; //64位程序



typedef struct _BUFFER_INFO {
	BYTE*  pBuffer;       //整个PE文件内存
	DWORD  dwBufferSize;  //PE文件大小
	HANDLE MappingHandle; //映射内存句柄
	BOOL   bFlag;         //标记是否应该清理内存
}BUFFER_INFO, *PBUFFER_INFO;

//Nt头由三部分组成  Signature，IMAGE_FILE_HEADER,IMAGE_OPTIONAL_HEADER
typedef struct _NT_HEADER {
	DWORD Signature;                                //PE文件标识
	IMAGE_FILE_HEADER FileHeader;                   //PE文件头
	IMAGE_OPTIONAL_HEADER32 OptionalHeader32;		//PE扩展头
	IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
	WORD  Magic;                                    //判断32位或64位程序标志
}NT_HEADER,*PNT_HEADER;

typedef struct _PE_INFO {
	DWORD   FileSize;    //文件大小
	CString CreatTime;   //文件创建时间
	CString AccessTime;  //文件最后访问时间
	CString ModifyTime;  //最后修改时间
	CString Attribute;
}PE_INFO, *PPE_INFO;

typedef struct _RESOURCES_TABLE {
	DWORD CodePage;
	DWORD OffsetToData;
	DWORD Size;
	PBUFFER_INFO  RespurcesInfo;
}RESOURCES_TABLE, *PRESPURCES_TABLE;


typedef struct _RESOURCES_MENU {
	UINT32 ID;
	UINT32 RVA;
	std::string     Name;
	RESOURCES_TABLE Resources;
}RESOURCES_MENU, *PRESOURCES_MENU;

typedef struct _SECTION_TABLE {
	std::string SectionName;                   //节表名
	UINT64      SectionBase;                   //偏移基地址
	PBUFFER_INFO         SectionInfo;
	IMAGE_SECTION_HEADER SectionHeader;
}SECTION_TABLE, *PSECTION_TABLE;

typedef struct _EXPORT_TABLE {
	DWORD   FunctionIndex;
	UINT64  FunctionAddress;
	std::string  FuncitonName;
	std::string  ModuleName;
}EXPORT_TABLE, *PEXPORT_TABLE;

typedef struct _IMPORT_TABLE {
	UINT64  FunctionAddress;
	std::string  FuncitonName;
	std::string  ModuleName;
}IMPORT_TABLE, *PIMPORT_TABLE;

enum RELOC_TYPE
{
	BASED_ABSOLUTE = 0,
	BASED_HIGH = 1,
	BASED_LOW = 2,
	BASED_HIGHLOW = 3,
	BASED_HIGHADJ = 4,
	BASED_MACHINE_SPECIFIC_5 = 5,
	BASED_RESERVED = 6,
	BASED_MACHINE_SPECIFIC_7 = 7,
	BASED_MACHINE_SPECIFIC_8 = 8,
	BASED_MACHINE_SPECIFIC_9 = 9,
	BASED_DIR64 = 10
};

typedef struct _BASERELOC_TABLE {
	UINT64      ItemAddress;   //绝对地址
	DWORD       AddressRVA;    //相对偏移
	DWORD       BlockSize;     //块大小
	RELOC_TYPE  Type;
}BASERELOC_TABLE, *PBASERELOC_TABLE;

typedef struct _PARSED_PE_TABLE {
	std::list<SECTION_TABLE>   SectionList;    //节表
	std::list<RESOURCES_MENU>  ResourcesList;  //资源表
	std::list<EXPORT_TABLE>    ExportList;     //导出表
	std::list<IMPORT_TABLE>    ImportList;     //导入表
	std::list<BASERELOC_TABLE> BaseRelocList;  //重定向表
}PARSED_PE_TABLE, *PPARSED_PE_TABLE;

typedef struct _PARSED_PE {
	PBUFFER_INFO     pPEDataInfo;
	PPARSED_PE_TABLE pTable;
	IMAGE_DOS_HEADER DosHeader;
	NT_HEADER        NtHeader;
}PARSED_PE,*PPARSED_PE;

typedef struct _RESSOURCES_NODE {
	std::string Id;
	struct _RESSOURCES_NODE *LeftNode;

}RESSOURCES_NODE,*PRESSOURCES_NODE;

class RessourcesTree
{
public:
	RessourcesTree()
	{

	}
	~RessourcesTree()
	{

	}

private:

};
