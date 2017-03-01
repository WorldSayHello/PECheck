#pragma once
#include "Common.h"
#include "Resources.h"

class CPEParse
{
public:
	DWORD   m_dwFileSize;
	PE_INFO m_PeInfo;
	HANDLE  m_PeFileHandle;
public:
	CPEParse();
	~CPEParse();
	BOOL GetFileInfo(PWSTR wszPEFilePath);
	BOOL ReadFileToBuffer(PWSTR wszPEFilePath, PBUFFER_INFO pPEInfo);
	BOOL GetDosHeader(PBUFFER_INFO pPEInfo, PIMAGE_DOS_HEADER pDosHeader, PBUFFER_INFO * ppRemainingData);
	BOOL ReadDosHeader(PBUFFER_INFO pDosHeaderInfo, PIMAGE_DOS_HEADER pDosHeader);
	BOOL GetNtHeader(PBUFFER_INFO pNtHeaderInfo, PNT_HEADER pNtHeader, PBUFFER_INFO * ppRemainingData);
	BOOL ReadNtHeader(PBUFFER_INFO pNtHeaderInfo, PNT_HEADER pNtHeader);
	BOOL ReadFileHeader(PBUFFER_INFO pFileHeaderInfo, PIMAGE_FILE_HEADER pFileHeader);
	BOOL ReadOptionalHeader32(PBUFFER_INFO pOptionalHeaderInfo, PIMAGE_OPTIONAL_HEADER32 pOptionalHeader);
	BOOL ReadOptionalHeader64(PBUFFER_INFO pOptionalHeaderInfo, PIMAGE_OPTIONAL_HEADER64 pOptionalHeader);
	PBUFFER_INFO SplitBuffer(PBUFFER_INFO pPEInfo, DWORD StartOffset, DWORD EndOffset);
	BOOL ReadByte(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PBYTE pData);
	BOOL ReadWord(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PWORD pData);
	BOOL ReadDword(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PDWORD pData);
	BOOL ReadQword(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PQWORD pData);
	VOID ReleaseSource(PBUFFER_INFO pBufferInfo);
	BOOL GetSections(PBUFFER_INFO pSectionInfo, PBUFFER_INFO pPEDataInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList);
	BOOL GetResources(PBUFFER_INFO pSectionInfo, PBUFFER_INFO pPEDataInfo, std::list<SECTION_TABLE>* SectionList, std::list<RESOURCES_MENU>* ResourcesList, CResources * ResourcesIDD);
	BOOL ReadResourcesTable(PBUFFER_INFO pResourcesInfo, DWORD Offset, DWORD SectionVirtualAddress, DWORD Depth, PIMAGE_RESOURCE_DIRECTORY_ENTRY Dirent, std::list<RESOURCES_MENU>* ResourcesList, CResources * ResourcesIDD);
	BOOL ParseResourceName(PBUFFER_INFO pSectionInfo, DWORD Offset, std::string & Data);
	BOOL GetExportTable(PBUFFER_INFO pExportTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<EXPORT_TABLE>* ExportList);
	BOOL GetImportTable(PBUFFER_INFO pImportTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<IMPORT_TABLE>* ImportList);
	BOOL GetBaseRelocTable(PBUFFER_INFO pBaseRelocTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<BASERELOC_TABLE>* BaseRelocList);
	BOOL GetSectionFromVA(std::list<SECTION_TABLE>* SectionList, UINT64 VirtualAddress, SECTION_TABLE * Section);
};

