#pragma once
#include "stdafx.h"
#include "afxdialogex.h"
#include <list>
#include <string>
#include <stdio.h>

#define WM_START_PARSE_PE WM_USER+100 //��ʼ����PE
#define WM_END_PARSE_PE   WM_USER+101 //��������PE

#define _offset(s,m) ((UINT32)&(((s*)0)->m))

const UINT16 NT_OPTIONAL_32_MAGIC = 0x10B; //32λ����
const UINT16 NT_OPTIONAL_64_MAGIC = 0x20B; //64λ����



typedef struct _BUFFER_INFO {
	BYTE*  pBuffer;       //����PE�ļ��ڴ�
	DWORD  dwBufferSize;  //PE�ļ���С
	HANDLE MappingHandle; //ӳ���ڴ���
	BOOL   bFlag;         //����Ƿ�Ӧ�������ڴ�
}BUFFER_INFO, *PBUFFER_INFO;

//Ntͷ�����������  Signature��IMAGE_FILE_HEADER,IMAGE_OPTIONAL_HEADER
typedef struct _NT_HEADER {
	DWORD Signature;                                //PE�ļ���ʶ
	IMAGE_FILE_HEADER FileHeader;                   //PE�ļ�ͷ
	IMAGE_OPTIONAL_HEADER32 OptionalHeader32;		//PE��չͷ
	IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
	WORD  Magic;                                    //�ж�32λ��64λ�����־
}NT_HEADER,*PNT_HEADER;

typedef struct _PE_INFO {
	DWORD   FileSize;    //�ļ���С
	CString CreatTime;   //�ļ�����ʱ��
	CString AccessTime;  //�ļ�������ʱ��
	CString ModifyTime;  //����޸�ʱ��
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
	std::string SectionName;                   //�ڱ���
	UINT64      SectionBase;                   //ƫ�ƻ���ַ
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
	UINT64      ItemAddress;   //���Ե�ַ
	DWORD       AddressRVA;    //���ƫ��
	DWORD       BlockSize;     //���С
	RELOC_TYPE  Type;
}BASERELOC_TABLE, *PBASERELOC_TABLE;

typedef struct _PARSED_PE_TABLE {
	std::list<SECTION_TABLE>   SectionList;    //�ڱ�
	std::list<RESOURCES_MENU>  ResourcesList;  //��Դ��
	std::list<EXPORT_TABLE>    ExportList;     //������
	std::list<IMPORT_TABLE>    ImportList;     //�����
	std::list<BASERELOC_TABLE> BaseRelocList;  //�ض����
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
