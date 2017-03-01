#include "stdafx.h"
#include "PEParse.h"


CPEParse::CPEParse()
{
	m_dwFileSize = 0;
}


CPEParse::~CPEParse()
{
}

BOOL CPEParse::GetFileInfo(PWSTR wszPEFilePath)
{
	//这里获得PE文件创建时间，修改时间，属性等信息
	CFileStatus FileStatus;
	if (CFile::GetStatus(wszPEFilePath, FileStatus))
	{
		m_PeInfo.FileSize   = FileStatus.m_size;                             //文件大小，字节
		m_PeInfo.CreatTime  = FileStatus.m_ctime.Format("%Y-%m-%d %H:%M:%S");//创建时间
		m_PeInfo.ModifyTime = FileStatus.m_mtime.Format("%Y-%m-%d %H:%M:%S");//修改时间
		m_PeInfo.AccessTime = FileStatus.m_atime.Format("%Y-%m-%d %H:%M:%S");//访问时间
		if ((FileStatus.m_attribute & 0x01) == 0x01)//判断是否只读
			m_PeInfo.Attribute += L"只读;";
		if ((FileStatus.m_attribute & 0x02) == 0x02)//判断是否隐藏
			m_PeInfo.Attribute += L"隐藏;";
		if ((FileStatus.m_attribute & 0x20) == 0x20)//判断是否存档
			m_PeInfo.Attribute += L"存档;";
		if ((FileStatus.m_attribute & 0x04) == 0x04)//判断是否是系统文件
			m_PeInfo.Attribute += L"系统文件;";
	}
	return TRUE;
}

//创建文件映射,将PE文件映射到内存
BOOL CPEParse::ReadFileToBuffer(PWSTR wszPEFilePath, PBUFFER_INFO pPEInfo)
{
	m_PeFileHandle = CreateFile(wszPEFilePath,              //文件路径
		GENERIC_READ,                                            //访问方式（读|写）
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,  //共享模式
		NULL,                         //指向安全属性的指针
		OPEN_EXISTING,                //如何创建(文件必须存在)
		FILE_ATTRIBUTE_NORMAL,        //文件属性(默认属性)
		NULL);                        //用于复制文件的句柄,指定之后操作在复制文件中进行
	if (m_PeFileHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	
	m_dwFileSize = GetFileSize(m_PeFileHandle, NULL);
	
	if (m_dwFileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(m_PeFileHandle);
		return FALSE;
	}

	if (pPEInfo == NULL)
	{
		CloseHandle(m_PeFileHandle);
		return FALSE;
	}

	memset(pPEInfo, 0, sizeof(BUFFER_INFO));
	//创建一个新的文件映射内核对象。
	HANDLE MappingHandle = CreateFileMapping(m_PeFileHandle,//创建映射的句柄
		NULL,//指定返回句柄是否可以被子进程所继承，制定一个安全对象，NULL表示默认安全对象
		PAGE_READONLY,//打开方式（只读）
		0,//文件映射最大长度的高32位
		0,//低32位
		NULL);//指定文件映射对象名字(创建一个无名映射对象)
	if (MappingHandle == NULL)
	{
		CloseHandle(m_PeFileHandle);
		return FALSE;
	}

	pPEInfo->MappingHandle = MappingHandle;
	//将一个文件映射对象映射到当前应用程序的地址空间。
	LPVOID VirtalAddress = MapViewOfFile(MappingHandle,//映像句柄
		FILE_MAP_READ,//访问方式
		0,//高32位
		0,//低32位
		0);//映射文件字节数

	if (VirtalAddress == NULL)
	{
		CloseHandle(MappingHandle);
		CloseHandle(m_PeFileHandle);
		return FALSE;
	}

	pPEInfo->bFlag      = FALSE;
	pPEInfo->pBuffer    = (BYTE*)VirtalAddress;
	pPEInfo->dwBufferSize = m_dwFileSize;

	CloseHandle(m_PeFileHandle);
	return TRUE;
}

//获取Dos头
BOOL CPEParse::GetDosHeader(PBUFFER_INFO pPEInfo, PIMAGE_DOS_HEADER pDosHeader, PBUFFER_INFO* ppRemainingData)
{
	if (pPEInfo == NULL)
	{
		return FALSE;
	}

	if (ReadDosHeader(pPEInfo, pDosHeader) == FALSE)
	{
		if (pPEInfo != NULL)
		{
			ReleaseSource(pPEInfo);
		}
		return FALSE;
	}

	DWORD Offset = 0;
	if (ReadDword(pPEInfo, _offset(IMAGE_DOS_HEADER, e_lfanew), &Offset) == FALSE)
	{
		return FALSE;
	}
	*ppRemainingData = SplitBuffer(pPEInfo, Offset, pPEInfo->dwBufferSize);
	return TRUE;
}

//读取DOS头
BOOL CPEParse::ReadDosHeader(PBUFFER_INFO pDosHeaderInfo, PIMAGE_DOS_HEADER pDosHeader)
{
	if (pDosHeaderInfo == NULL)
	{
		return FALSE;
	}

	WORD Magic = 0;

	//判断是否是MZ
	if (ReadWord(pDosHeaderInfo, 0, &Magic) == FALSE || Magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBox(NULL, L"该文件不是PE文件!", L"警告", MB_OK);
		return FALSE;
	}
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_magic), &pDosHeader->e_magic);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_cblp), &pDosHeader->e_cblp);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_cp), &pDosHeader->e_cp);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_crlc), &pDosHeader->e_crlc);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_cparhdr), &pDosHeader->e_cparhdr);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_minalloc), &pDosHeader->e_minalloc);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_maxalloc), &pDosHeader->e_maxalloc);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_ss), &pDosHeader->e_ss);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_sp), &pDosHeader->e_sp);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_cp), &pDosHeader->e_cp);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_csum), &pDosHeader->e_csum);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_ip), &pDosHeader->e_ip);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_cs), &pDosHeader->e_cs);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_lfarlc), &pDosHeader->e_lfarlc);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_ovno), &pDosHeader->e_ovno);
	for (DWORD i = 0; i<4; i++)
	{
		ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_res[i]), &pDosHeader->e_res[i]);
	}
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_oemid), &pDosHeader->e_oemid);
	ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_oeminfo), &pDosHeader->e_oeminfo);
	for (DWORD i = 0; i<10; i++)
	{
		ReadWord(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_res2[i]), &pDosHeader->e_res2[i]);
	}
	ReadDword(pDosHeaderInfo, _offset(IMAGE_DOS_HEADER, e_lfanew), (PDWORD)&pDosHeader->e_lfanew);
	return TRUE;
}

//获取Nt头部信息（Signature，PE头，扩展PE头）
BOOL CPEParse::GetNtHeader(PBUFFER_INFO pNtHeaderInfo, PNT_HEADER pNtHeader, PBUFFER_INFO* ppRemainingData)
{
	if (pNtHeaderInfo == NULL)
	{
		return FALSE;
	}

	if (ReadNtHeader(pNtHeaderInfo, pNtHeader) == FALSE)
	{
		if (pNtHeaderInfo != NULL)
		{
			ReleaseSource(pNtHeaderInfo);
		}
		return FALSE;
	}
	DWORD Offset = 0;
	if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
	{
		Offset = sizeof(UINT32) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
	}
	else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
	{
		Offset = sizeof(UINT32) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
	}
	else
	{
		ReleaseSource(pNtHeaderInfo);
		return FALSE;
	}
	*ppRemainingData = SplitBuffer(pNtHeaderInfo, Offset, pNtHeaderInfo->dwBufferSize);
	ReleaseSource(pNtHeaderInfo);

	return TRUE;
}

//读取NT头
BOOL CPEParse::ReadNtHeader(PBUFFER_INFO pNtHeaderInfo, PNT_HEADER pNtHeader)
{
	if (pNtHeaderInfo == NULL)
	{
		return FALSE;
	}

	DWORD Signature = 0;

	//判断是否是PE00
	if (ReadDword(pNtHeaderInfo, 0, &Signature) == FALSE || Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	pNtHeader->Signature = Signature;  //PE文件标识
	PBUFFER_INFO pFileHeaderInfo = SplitBuffer(pNtHeaderInfo, _offset(NT_HEADER, FileHeader), pNtHeaderInfo->dwBufferSize);

	if (pFileHeaderInfo == NULL)
	{
		return FALSE;
	}

	if (ReadFileHeader(pFileHeaderInfo, &pNtHeader->FileHeader) == FALSE)
	{
		ReleaseSource(pFileHeaderInfo);
		return FALSE;
	}

	PBUFFER_INFO pOptionalHeader = SplitBuffer(pNtHeaderInfo, _offset(NT_HEADER, OptionalHeader32), pNtHeaderInfo->dwBufferSize);

	if (pOptionalHeader == NULL)
	{
		ReleaseSource(pFileHeaderInfo);
		return FALSE;
	}

	if (ReadWord(pOptionalHeader, 0, &pNtHeader->Magic) == FALSE)
	{
		if (pOptionalHeader != NULL)
		{
			ReleaseSource(pOptionalHeader);
		}
		ReleaseSource(pFileHeaderInfo);

		return FALSE;
	}
	if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
	{
		if (ReadOptionalHeader32(pOptionalHeader, &pNtHeader->OptionalHeader32) == FALSE)
		{
			ReleaseSource(pOptionalHeader);
			ReleaseSource(pFileHeaderInfo);
			return FALSE;
		}
	}
	else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
	{
		if (ReadOptionalHeader64(pOptionalHeader, &pNtHeader->OptionalHeader64) == FALSE)
		{
			ReleaseSource(pOptionalHeader);
			ReleaseSource(pFileHeaderInfo);
			return FALSE;
		}
	}
	else
	{
		ReleaseSource(pOptionalHeader);
		ReleaseSource(pFileHeaderInfo);
		return FALSE;
	}

	ReleaseSource(pOptionalHeader);
	ReleaseSource(pFileHeaderInfo);

	return TRUE;
}

//读取标准PE头
BOOL CPEParse::ReadFileHeader(PBUFFER_INFO pFileHeaderInfo, PIMAGE_FILE_HEADER pFileHeader)
{
	ReadWord(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, Machine), &pFileHeader->Machine);
	ReadWord(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, NumberOfSections), &pFileHeader->NumberOfSections);
	ReadDword(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, TimeDateStamp), &pFileHeader->TimeDateStamp);
	ReadDword(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, PointerToSymbolTable), &pFileHeader->PointerToSymbolTable);
	ReadDword(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, NumberOfSymbols), &pFileHeader->NumberOfSymbols);
	ReadWord(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, SizeOfOptionalHeader), &pFileHeader->SizeOfOptionalHeader);
	ReadWord(pFileHeaderInfo, _offset(IMAGE_FILE_HEADER, Characteristics), &pFileHeader->Characteristics);
	return TRUE;
}

//读取PE扩展头 32位PE
BOOL CPEParse::ReadOptionalHeader32(PBUFFER_INFO pOptionalHeaderInfo, PIMAGE_OPTIONAL_HEADER32 pOptionalHeader)
{
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, Magic), &pOptionalHeader->Magic);
	ReadByte(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MajorLinkerVersion), &pOptionalHeader->MajorLinkerVersion);
	ReadByte(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MinorLinkerVersion), &pOptionalHeader->MinorLinkerVersion);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfCode), &pOptionalHeader->SizeOfCode);   //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfInitializedData), &pOptionalHeader->SizeOfInitializedData);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfUninitializedData), &pOptionalHeader->SizeOfUninitializedData);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint), &pOptionalHeader->AddressOfEntryPoint);  //OEP
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, BaseOfCode), &pOptionalHeader->BaseOfCode);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, BaseOfData), &pOptionalHeader->BaseOfData);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, ImageBase), &pOptionalHeader->ImageBase);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SectionAlignment), &pOptionalHeader->SectionAlignment);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, FileAlignment), &pOptionalHeader->FileAlignment);        //
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MajorOperatingSystemVersion), &pOptionalHeader->MajorOperatingSystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MinorOperatingSystemVersion), &pOptionalHeader->MinorOperatingSystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MajorImageVersion), &pOptionalHeader->MajorImageVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MinorImageVersion), &pOptionalHeader->MinorImageVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MajorSubsystemVersion), &pOptionalHeader->MajorSubsystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, MinorSubsystemVersion), &pOptionalHeader->MinorSubsystemVersion);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, Win32VersionValue), &pOptionalHeader->Win32VersionValue);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfImage), &pOptionalHeader->SizeOfImage);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders), &pOptionalHeader->SizeOfHeaders);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, CheckSum), &pOptionalHeader->CheckSum);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, Subsystem), &pOptionalHeader->Subsystem);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, DllCharacteristics), &pOptionalHeader->DllCharacteristics);//
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfStackReserve), &pOptionalHeader->SizeOfStackReserve);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfStackCommit), &pOptionalHeader->SizeOfStackCommit);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfHeapReserve), &pOptionalHeader->SizeOfHeapReserve);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, SizeOfHeapCommit), &pOptionalHeader->SizeOfHeapCommit);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, LoaderFlags), &pOptionalHeader->LoaderFlags);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes), &pOptionalHeader->NumberOfRvaAndSizes);

	for (UINT32 i = 0; i<pOptionalHeader->NumberOfRvaAndSizes; i++)
	{
		UINT32 Offset = (i * sizeof(IMAGE_DATA_DIRECTORY));
		Offset += _offset(IMAGE_OPTIONAL_HEADER32, DataDirectory[0]);

		UINT32 v1 = 0;
		//读偏移RVA
		v1 = Offset + _offset(IMAGE_DATA_DIRECTORY, VirtualAddress);
		if (ReadDword(pOptionalHeaderInfo, v1, &(pOptionalHeader->DataDirectory[i].VirtualAddress)) == FALSE)
		{
			return FALSE;
		}
		v1 = Offset + _offset(IMAGE_DATA_DIRECTORY, Size);
		if (ReadDword(pOptionalHeaderInfo, v1, &(pOptionalHeader->DataDirectory[i].Size)) == FALSE)
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL CPEParse::ReadOptionalHeader64(PBUFFER_INFO pOptionalHeaderInfo, PIMAGE_OPTIONAL_HEADER64 pOptionalHeader)
{
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, Magic), &pOptionalHeader->Magic);
	ReadByte(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MajorLinkerVersion), &pOptionalHeader->MajorLinkerVersion);
	ReadByte(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MinorLinkerVersion), &pOptionalHeader->MinorLinkerVersion);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfCode), &pOptionalHeader->SizeOfCode);   //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfInitializedData), &pOptionalHeader->SizeOfInitializedData);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfUninitializedData), &pOptionalHeader->SizeOfUninitializedData);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint), &pOptionalHeader->AddressOfEntryPoint);  //OEP
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, BaseOfCode), &pOptionalHeader->BaseOfCode);
	ReadQword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, ImageBase), &pOptionalHeader->ImageBase);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SectionAlignment), &pOptionalHeader->SectionAlignment);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, FileAlignment), &pOptionalHeader->FileAlignment);        //	
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MajorOperatingSystemVersion), &pOptionalHeader->MajorOperatingSystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MinorOperatingSystemVersion), &pOptionalHeader->MinorOperatingSystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MajorImageVersion), &pOptionalHeader->MajorImageVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MinorImageVersion), &pOptionalHeader->MinorImageVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MajorSubsystemVersion), &pOptionalHeader->MajorSubsystemVersion);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, MinorSubsystemVersion), &pOptionalHeader->MinorSubsystemVersion);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, Win32VersionValue), &pOptionalHeader->Win32VersionValue);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfImage), &pOptionalHeader->SizeOfImage);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders), &pOptionalHeader->SizeOfHeaders);  //
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, CheckSum), &pOptionalHeader->CheckSum);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, Subsystem), &pOptionalHeader->Subsystem);
	ReadWord(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, DllCharacteristics), &pOptionalHeader->DllCharacteristics);//	
	ReadQword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfStackReserve), &pOptionalHeader->SizeOfStackReserve);
	ReadQword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfStackCommit), &pOptionalHeader->SizeOfStackCommit);
	ReadQword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfHeapReserve), &pOptionalHeader->SizeOfHeapReserve);
	ReadQword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, SizeOfHeapCommit), &pOptionalHeader->SizeOfHeapCommit);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, LoaderFlags), &pOptionalHeader->LoaderFlags);
	ReadDword(pOptionalHeaderInfo, _offset(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes), &pOptionalHeader->NumberOfRvaAndSizes);

	for (UINT32 i = 0; i<pOptionalHeader->NumberOfRvaAndSizes; i++)   //当前PE用到多少个目录
	{
		UINT32  Offset = (i * sizeof(IMAGE_DATA_DIRECTORY));  //i*数据目录项
		Offset += _offset(IMAGE_OPTIONAL_HEADER64, DataDirectory[0]);

		UINT32  v1 = 0;

		v1 = Offset + _offset(IMAGE_DATA_DIRECTORY, VirtualAddress);
		if (ReadDword(pOptionalHeaderInfo, v1, &(pOptionalHeader->DataDirectory[i].VirtualAddress)) == FALSE)
		{
			return FALSE;
		}

		v1 = Offset + _offset(IMAGE_DATA_DIRECTORY, Size);
		if (ReadDword(pOptionalHeaderInfo, v1, &(pOptionalHeader->DataDirectory[i].Size)) == FALSE)
		{
			return FALSE;
		}
	}

	return TRUE;
}

//分割数据
PBUFFER_INFO CPEParse::SplitBuffer(PBUFFER_INFO pBufferInfo, DWORD StartOffset, DWORD EndOffset)
{
	if (pBufferInfo == NULL)
	{
		return NULL;
	}
	if (EndOffset<StartOffset || EndOffset>pBufferInfo->dwBufferSize)
	{
		return NULL;
	}

	PBUFFER_INFO v1 = new BUFFER_INFO();
	if (v1 == NULL)
	{
		return NULL;
	}
	v1->bFlag = TRUE;
	v1->pBuffer = pBufferInfo->pBuffer + StartOffset;
	v1->dwBufferSize = EndOffset - StartOffset;

	return v1;
}

//按单字节读
BOOL CPEParse::ReadByte(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PBYTE pData)
{

	if (pBufferInfo == NULL)
	{
		return FALSE;
	}
	if (dwOffset >= pBufferInfo->dwBufferSize)
	{
		return FALSE;
	}

	PBYTE v1 = (PBYTE)(pBufferInfo->pBuffer + dwOffset);
	*pData = *v1;

	return TRUE;
}


//按2字节读
BOOL CPEParse::ReadWord(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PWORD pData)
{
	if (pBufferInfo == NULL)
	{
		return FALSE;
	}
	if (dwOffset >= pBufferInfo->dwBufferSize)
	{
		return FALSE;
	}
	PWORD v1 = (PWORD)(pBufferInfo->pBuffer + dwOffset);
	*pData = *v1;
	return TRUE;
}

//按4字节读
BOOL CPEParse::ReadDword(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PDWORD pData)
{

	if (pBufferInfo == NULL)
	{
		return FALSE;
	}
	if (dwOffset >= pBufferInfo->dwBufferSize)
	{
		return FALSE;
	}

	PDWORD v1 = PDWORD(pBufferInfo->pBuffer + dwOffset);
	*pData = *v1;

	return TRUE;
}

//按8字节读
BOOL CPEParse::ReadQword(PBUFFER_INFO pBufferInfo, DWORD dwOffset, PQWORD pData)
{

	if (pBufferInfo == NULL)
	{
		return FALSE;
	}
	if (dwOffset >= pBufferInfo->dwBufferSize)
	{
		return FALSE;
	}

	PQWORD v1 = (PQWORD)(pBufferInfo->pBuffer + dwOffset);
	*pData = *v1;

	return TRUE;
}

//释放缓冲区资源
VOID CPEParse::ReleaseSource(PBUFFER_INFO pBufferInfo)
{
	/*if (pBufferInfo == NULL)
	{
		return;
	}

	if (pBufferInfo->bFlag == FALSE)
	{
		UnmapViewOfFile(pBufferInfo->pBuffer);
		CloseHandle(pBufferInfo->MappingHandle);
	}
	delete pBufferInfo;*/
}

//获得节表
BOOL CPEParse::GetSections(PBUFFER_INFO pSectionInfo,PBUFFER_INFO pPEDataInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList)
{
	if (pSectionInfo == NULL)
	{
		return FALSE;
	}

	for (UINT32 i = 0; i<pNtHeader->FileHeader.NumberOfSections; i++)//标准PE头中的NumberOfSections记录了多少个节
	{
		IMAGE_SECTION_HEADER SectionHeader;

		UINT32 Offset = i * sizeof(IMAGE_SECTION_HEADER);
		for (UINT32 k = 0; k<IMAGE_SIZEOF_SHORT_NAME; k++)
		{
			if (ReadByte(pSectionInfo, Offset + k, &SectionHeader.Name[k]) == FALSE)
			{
				return FALSE;
			}
		}
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, Misc.VirtualSize), &SectionHeader.Misc.VirtualSize);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, VirtualAddress), &SectionHeader.VirtualAddress);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, SizeOfRawData), &SectionHeader.SizeOfRawData);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, PointerToRawData), &SectionHeader.PointerToRawData);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, PointerToRelocations), &SectionHeader.PointerToRelocations);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, PointerToLinenumbers), &SectionHeader.PointerToLinenumbers);
		ReadWord(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, NumberOfRelocations), &SectionHeader.NumberOfRelocations);
		ReadWord(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, NumberOfLinenumbers), &SectionHeader.NumberOfLinenumbers);
		ReadDword(pSectionInfo, Offset + _offset(IMAGE_SECTION_HEADER, Characteristics), &SectionHeader.Characteristics);

		SECTION_TABLE Section;
		for (UINT32 i = 0; i<IMAGE_SIZEOF_SHORT_NAME; i++)
		{
			UINT8 v1 = SectionHeader.Name[i];

			if (v1 == 0)
			{
				break;
			}

			Section.SectionName += v1;
		}

		if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
		{
			Section.SectionBase = pNtHeader->OptionalHeader32.ImageBase + SectionHeader.VirtualAddress;

		}
		else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
		{
			Section.SectionBase = pNtHeader->OptionalHeader64.ImageBase + SectionHeader.VirtualAddress;
		}
		else
		{
			return FALSE;
		}

		Section.SectionHeader = SectionHeader;
		UINT32 SectionStart = SectionHeader.PointerToRawData; //文件上节数据起始位置 .txt

		UINT32 SectionEnd = SectionStart + SectionHeader.SizeOfRawData;

		Section.SectionInfo = SplitBuffer(pPEDataInfo, SectionStart, SectionEnd);

		SectionList->push_back(Section);//装入模板
	}

}

//获得资源表
BOOL CPEParse::GetResources(PBUFFER_INFO pSectionInfo, PBUFFER_INFO pPEDataInfo, std::list<SECTION_TABLE>* SectionList, std::list<RESOURCES_MENU>* ResourcesList,CResources* ResourcesIDD)
{
	if (!pSectionInfo)
	{
		return FALSE;
	}
	for (std::list<SECTION_TABLE>::iterator v1 = SectionList->begin(); v1 != SectionList->end(); ++v1)
	{
		SECTION_TABLE Section = *v1;
		if (Section.SectionName != ".rsrc")  //SectionList[2]
		{
			continue;
		}
		if (ReadResourcesTable(Section.SectionInfo, 0, Section.SectionHeader.VirtualAddress, 0, NULL, ResourcesList, ResourcesIDD) == FALSE)
		{
			return FALSE;
		}
		break;
	}
	return TRUE;
}

HTREEITEM hRoot = NULL;
HTREEITEM hItem = NULL;
//解析资源表
BOOL CPEParse::ReadResourcesTable(PBUFFER_INFO pResourcesInfo,
	DWORD Offset,
	DWORD SectionVirtualAddress,
	DWORD Depth,
	PIMAGE_RESOURCE_DIRECTORY_ENTRY Dirent,
	std::list<RESOURCES_MENU>* ResourcesList,
	CResources* ResourcesIDD)
{
	if (!pResourcesInfo)
	{
		return FALSE;
	}
	IMAGE_RESOURCE_DIRECTORY ResourcesDirTable = { 0 };
	ReadDword(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, Characteristics), &ResourcesDirTable.Characteristics);          //属性(保留，为0)
	ReadDword(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, TimeDateStamp), &ResourcesDirTable.TimeDateStamp);              //时间戳
	ReadWord(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, MajorVersion), &ResourcesDirTable.MajorVersion);                 //版本
	ReadWord(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, MinorVersion), &ResourcesDirTable.MinorVersion);
	ReadWord(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, NumberOfNamedEntries), &ResourcesDirTable.NumberOfNamedEntries); //以名称命名的下级目录
	ReadWord(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY, NumberOfIdEntries), &ResourcesDirTable.NumberOfIdEntries);       //以ID命名的下级目录

	if (!ResourcesDirTable.NumberOfNamedEntries && !ResourcesDirTable.NumberOfIdEntries)
	{
		return FALSE;
	}
	DWORD i = 0;
	Offset += sizeof(IMAGE_RESOURCE_DIRECTORY);

	for (i = 0; i<ResourcesDirTable.NumberOfNamedEntries + ResourcesDirTable.NumberOfIdEntries; i++)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourcesDirEntry = NULL;
		RESOURCES_MENU ResourcesMenu = {};
		if (!Dirent)
		{
			pResourcesDirEntry = new IMAGE_RESOURCE_DIRECTORY_ENTRY();
			if (!pResourcesDirEntry)
			{
				return FALSE;
			}
			memset(pResourcesDirEntry, 0, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
		}
		else
		{
			pResourcesDirEntry = Dirent;
		}
		/*该结构使用了UNION类型，其实包含两项，
		（1）目录项的ID或名字；
		当该字段最高位为1时，表示一个非标准命名，用Name表示，由该字段的低31位组成一个偏移值，该偏移值是相对于资源基地址的特殊偏移地址
		当该字段最高位为0时，表示一个标准命名，用ID表示，由该字段的低16位表示一个ID值，该ID表示一个系统定义好的资源
		（2）描述资源数据块的指针；
		字段第31位为1，为一个偏移值，指向下一个目录
		字段第31位为0，指向一个数据项IMAGE_RESOURCE_DATA_ENTRY*/
		ReadDword(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY_ENTRY, Name), &pResourcesDirEntry->Name);
		ReadDword(pResourcesInfo, Offset + _offset(IMAGE_RESOURCE_DIRECTORY_ENTRY, OffsetToData), &pResourcesDirEntry->OffsetToData);

		Offset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

		
		if (Depth == 0)
		{
			if (pResourcesDirEntry->NameIsString)  //‭‬获得最高位是否为1
			{
				//去掉首地址，获得偏移值
				if (!ParseResourceName(pResourcesInfo, pResourcesDirEntry->NameOffset, ResourcesMenu.Name))
				{					
					return FALSE;
				}
				CString v1;
				v1.Format(L"%s", ResourcesMenu.Name.c_str());
				hRoot = ResourcesIDD->m_SectionTree.InsertItem(v1, TVI_ROOT, TVI_LAST);
			}
			else
			{
				ResourcesMenu.ID = pResourcesDirEntry->Id;
				CString v1;
				switch (pResourcesDirEntry->Id)
				{
				case 1:  v1 = "Cursor"; break;
				case 2:  v1 = L"Bitmap"; break;
				case 3:  v1 = L"Icon"; break;
				case 4:  v1 = L"Menu"; break;
				case 5:  v1 = L"Dialog"; break;
				case 6:  v1 = L"String"; break;
				case 7:  v1 = L"FontDir"; break;
				case 8:  v1 = L"Font"; break;
				case 9:  v1 = L"Accelerator"; break;
				case 10: v1 = L"RCDATA"; break;
				case 11: v1 = L"MessageTable"; break;
				case 12: v1 = L"GroupCursor"; break;
				case 14: v1 = L"GroupIcon"; break;
				case 16: v1 = L"Version"; break;
				case 17: v1 = L"DlgInclude"; break;
				case 19: v1 = L"PlugPlay"; break;
				case 20: v1 = L"VXD"; break;
				case 21: v1 = L"ANICursor"; break;
				case 22: v1 = L"ANIIcon"; break;
				case 23: v1 = L"HTML"; break;
				default:
					v1.Format(L"ID:%d", pResourcesDirEntry->Id);
					break;
				}
				
				hRoot = ResourcesIDD->m_SectionTree.InsertItem(v1, TVI_ROOT, TVI_LAST);

			}	
		}
		else if (Depth == 1)
		{
			
			if (i<ResourcesDirTable.NumberOfNamedEntries)
			{
				if (!ParseResourceName(pResourcesInfo, pResourcesDirEntry->NameOffset, ResourcesMenu.Name))
				{
					return FALSE;
				}
				CString v1;
				v1.Format(L"%S", ResourcesMenu.Name.c_str());
				hItem = ResourcesIDD->m_SectionTree.InsertItem(v1, hRoot, TVI_LAST);
			}
			else
			{
				CString v1;
				ResourcesMenu.ID = pResourcesDirEntry->Id;
				v1.Format(L"ID:%d", pResourcesDirEntry->Id);
				hItem = ResourcesIDD->m_SectionTree.InsertItem(v1, hRoot, TVI_LAST);
			}
		}
		else if (Depth == 2)
		{
			if (i < ResourcesDirTable.NumberOfNamedEntries)
			{
				if (!ParseResourceName(pResourcesInfo, pResourcesDirEntry->NameOffset, ResourcesMenu.Name))
				{
					return FALSE;
				}	
				CString v1;
				v1.Format(L"%S", ResourcesMenu.Name.c_str());
				hItem = ResourcesIDD->m_SectionTree.InsertItem(v1, hRoot, TVI_LAST);
			}
			else
			{
				CString v1;
				ResourcesMenu.ID = pResourcesDirEntry->Id;
				v1.Format(L"ID:%d", pResourcesDirEntry->Id);
				hItem = ResourcesIDD->m_SectionTree.InsertItem(v1, hItem, TVI_LAST);
			}
			
		}
		if (pResourcesDirEntry->DataIsDirectory)  //‭‬获得最高位是否为1
		{			
			if (ReadResourcesTable(pResourcesInfo, pResourcesDirEntry->OffsetToDirectory, SectionVirtualAddress, Depth+1,  //Depth+1
				pResourcesDirEntry, ResourcesList, ResourcesIDD) == FALSE)
			{
				return FALSE;
			}
		}
		else
		{
			IMAGE_RESOURCE_DATA_ENTRY ResourcesDataEntry;

			ReadDword(pResourcesInfo, pResourcesDirEntry->OffsetToData + _offset(IMAGE_RESOURCE_DATA_ENTRY, OffsetToData), &ResourcesDataEntry.OffsetToData);//资源数据RVA
			ReadDword(pResourcesInfo, pResourcesDirEntry->OffsetToData + _offset(IMAGE_RESOURCE_DATA_ENTRY, Size), &ResourcesDataEntry.Size);         //资源数据长度
			ReadDword(pResourcesInfo, pResourcesDirEntry->OffsetToData + _offset(IMAGE_RESOURCE_DATA_ENTRY, CodePage), &ResourcesDataEntry.CodePage); //代码页
			ReadDword(pResourcesInfo, pResourcesDirEntry->OffsetToData + _offset(IMAGE_RESOURCE_DATA_ENTRY, Reserved), &ResourcesDataEntry.Reserved); //保留字段
			
            //进入模板
			RESOURCES_TABLE Resources = {};

			Resources.OffsetToData = ResourcesDataEntry.OffsetToData;
			Resources.Size = ResourcesDataEntry.Size;
			Resources.CodePage = ResourcesDataEntry.CodePage;

			DWORD Start = ResourcesDataEntry.OffsetToData - SectionVirtualAddress;        //  2 = 102-100           200 = 100 -                   

			if (Start>ResourcesDataEntry.OffsetToData)
			{
				Resources.RespurcesInfo = SplitBuffer(pResourcesInfo, 0, 0);   //错误
			}
			else
			{
				Resources.RespurcesInfo = SplitBuffer(pResourcesInfo, Start, Start + ResourcesDataEntry.Size);

				if (!Resources.RespurcesInfo)
				{
					Resources.RespurcesInfo = SplitBuffer(pResourcesInfo, 0, 0);
				}

			}
			if (!Resources.RespurcesInfo)
			{
				return FALSE;
			}
			CString v1;
			v1.Format(L"资源数据RVA:0x%X,    资源数据长度:0x%X,   资源数据代码页:%d",Resources.OffsetToData, Resources.Size, Resources.CodePage);
			ResourcesIDD->m_SectionTree.InsertItem(v1, hItem, TVI_LAST);
		}
	}
	return TRUE;
}

//解析出名字内容
BOOL CPEParse::ParseResourceName(PBUFFER_INFO pSectionInfo, DWORD Offset, std::string& Data)
{
	BYTE   v1;
	WORD   Length = 0;

	if (ReadWord(pSectionInfo, Offset, &Length) == FALSE)
	{
		return FALSE;
	}
	Offset += 2;  //过word
	for (int i = 0; i<Length*2 ; i++)
	{
		if (ReadByte(pSectionInfo, Offset + i, &v1) == FALSE)
		{
			return FALSE;
		}

		Data += v1;
	}
	Data += '\0';
	return TRUE;
}

//获得导出表
DWORD Index = 0;  //记录导出函数序号索引
BOOL CPEParse::GetExportTable(PBUFFER_INFO pExportTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<EXPORT_TABLE>* ExportList)
{
	//导出表 Dll
	IMAGE_DATA_DIRECTORY ExportDataDir = {};

	//名称索引表
	SECTION_TABLE FunctionAddressTableSection;
	DWORD FunctionAddressTableOffset;
	

	if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
	{
		ExportDataDir = pNtHeader->OptionalHeader32.DataDirectory[0];
	}
	else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
	{
		ExportDataDir = pNtHeader->OptionalHeader64.DataDirectory[0];
	}
	else
	{
		ReleaseSource(pExportTableInfo);
		
		return FALSE;
	}

	UINT64 VirtualAddress = 0;//导出表的绝对地址
	if (ExportDataDir.Size != 0)
	{
		if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
		{
			VirtualAddress = ExportDataDir.VirtualAddress + pNtHeader->OptionalHeader32.ImageBase;
		}
		else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
		{
			VirtualAddress = ExportDataDir.VirtualAddress + pNtHeader->OptionalHeader64.ImageBase;
		}
		else
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}

		SECTION_TABLE ExportDataDirSection = {};//导出表所属的节
		if (GetSectionFromVA(SectionList, VirtualAddress, &ExportDataDirSection) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}

		DWORD  ExportDataDirOffset = VirtualAddress - ExportDataDirSection.SectionBase;
		DWORD  ModuleNameRVA = 0;     //模块名称偏移地址

		if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, Name), &ModuleNameRVA) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}

		//导出函数索引不一定是从0开始的，它是从Base开始的，实际索引值应该是当前序列+Base的值
		DWORD Base = 0;
		if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, Base), &Base) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}
		UINT64 ModuleNameVA = 0;      //模块绝对地址
		if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
		{
			ModuleNameVA = ModuleNameRVA + pNtHeader->OptionalHeader32.ImageBase;
		}
		else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
		{
			ModuleNameVA = ModuleNameRVA + pNtHeader->OptionalHeader64.ImageBase;
		}
		else
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}

		SECTION_TABLE ModuleNameSection = {};

		if (GetSectionFromVA(SectionList, ModuleNameVA, &ModuleNameSection) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}

		DWORD ModuleNameOffset = 0;
		ModuleNameOffset = ModuleNameVA - ModuleNameSection.SectionBase;

		BYTE v1 = 0;
		std::string ModuleName;
		do
		{	
			if (ReadByte(ModuleNameSection.SectionInfo, ModuleNameOffset, &v1) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}
			if (v1 == 0)
			{
				break;
			}
			ModuleName.push_back(v1);
			ModuleNameOffset++;
		} while (true);

		//得到导出的函数总数
		DWORD NumberOfFunctions = 0;
		if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions), &NumberOfFunctions) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}
		//按照名称导出函数个数
		DWORD  NumberOfNames = 0;
		if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, NumberOfNames), &NumberOfNames) == FALSE)
		{
			ReleaseSource(pExportTableInfo);
			return FALSE;
		}


		BOOL *bOk = NULL;
		//由序号导出
		if (NumberOfFunctions > 0)
		{
			bOk = (BOOL*)malloc(NumberOfFunctions*sizeof(BOOL));
			
			memset(bOk, 0, sizeof(BOOL)*NumberOfFunctions);
		}


		//按名称导出
		if (NumberOfNames > 0)
		{
			DWORD AddressOfNamesRVA;

			if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, AddressOfNames), &AddressOfNamesRVA) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}

			//函数名称表的绝对地址
			UINT64 AddressOfNameVA;
			if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
			{
				AddressOfNameVA = AddressOfNamesRVA + pNtHeader->OptionalHeader32.ImageBase;
			}
			else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
			{
				AddressOfNameVA = AddressOfNamesRVA + pNtHeader->OptionalHeader64.ImageBase;
			}
			else
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}
			SECTION_TABLE NameAddressTableSection;
			if (GetSectionFromVA(SectionList, AddressOfNameVA, &NameAddressTableSection) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}
			DWORD NameAddressTableOffset = AddressOfNameVA - NameAddressTableSection.SectionBase;

			//函数地址表
			DWORD AddressOfFunctionsRVA = 0;
			if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions), &AddressOfFunctionsRVA) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}
			//绝对地址
			UINT64 AddressOfFunctionsVA = 0;
			if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
			{
				AddressOfFunctionsVA = AddressOfFunctionsRVA + pNtHeader->OptionalHeader32.ImageBase;
			}
			else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
			{
				AddressOfFunctionsVA = AddressOfFunctionsRVA + pNtHeader->OptionalHeader64.ImageBase;
			}
			else
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}

			
			if (GetSectionFromVA(SectionList, AddressOfFunctionsVA, &FunctionAddressTableSection) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}
			FunctionAddressTableOffset = AddressOfFunctionsVA - FunctionAddressTableSection.SectionBase;

			//名称索引表
			DWORD AddressOfNameOrdinalsRVA = 0;
			if (ReadDword(ExportDataDirSection.SectionInfo, ExportDataDirOffset + _offset(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals), &AddressOfNameOrdinalsRVA) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}

			UINT64 AddressOfNameOrdinalsVA = 0;
			if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
			{
				AddressOfNameOrdinalsVA = AddressOfNameOrdinalsRVA + pNtHeader->OptionalHeader32.ImageBase;
			}
			else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
			{
				AddressOfNameOrdinalsVA = AddressOfNameOrdinalsRVA + pNtHeader->OptionalHeader64.ImageBase;
			}
			else
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}

			//函数序号地址表
			SECTION_TABLE     NameOrdinalAddressTableSection;
			if (GetSectionFromVA(SectionList, AddressOfNameOrdinalsVA, &NameOrdinalAddressTableSection) == FALSE)
			{
				ReleaseSource(pExportTableInfo);
				return FALSE;
			}

			DWORD NameOrdinalAddressTableOffset = AddressOfNameOrdinalsVA - NameOrdinalAddressTableSection.SectionBase;

			//遍历
			for (UINT32 i = 0; i<NumberOfNames; i++)
			{
				std::string FunctionName;
				DWORD       CurrentNameRVA;
				if (ReadDword(NameAddressTableSection.SectionInfo, NameAddressTableOffset + (i * sizeof(DWORD)), &CurrentNameRVA) == FALSE)
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}

				UINT64 CurrentNameVA;
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
				{
					CurrentNameVA = CurrentNameRVA + pNtHeader->OptionalHeader32.ImageBase;
				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{
					CurrentNameVA = CurrentNameRVA + pNtHeader->OptionalHeader64.ImageBase;
				}
				else
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}

				SECTION_TABLE     CurrentNameSection;
				if (GetSectionFromVA(SectionList, CurrentNameVA, &CurrentNameSection) == FALSE)
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}

				UINT32 CurrentNameOffset = CurrentNameVA - CurrentNameSection.SectionBase;
				do {
					if (ReadByte(CurrentNameSection.SectionInfo, CurrentNameOffset, &v1) == FALSE) 
					{
						ReleaseSource(pExportTableInfo);
						return FALSE;
					}
					if (v1 == 0)
					{
						break;
					}

					FunctionName.push_back(v1);

					CurrentNameOffset++;
				} while (true);

				WORD  Ordinal;
				if (ReadWord(NameOrdinalAddressTableSection.SectionInfo,
					NameOrdinalAddressTableOffset + (i * sizeof(WORD)),
					&Ordinal) == FALSE)
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}

				bOk[Ordinal] = TRUE;
				DWORD v2 = (Ordinal * sizeof(DWORD));

				DWORD  FunctionAddressRVA;
				if (ReadDword(FunctionAddressTableSection.SectionInfo, FunctionAddressTableOffset + v2, &FunctionAddressRVA) == FALSE)
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}

				BOOL  isForwarded =
					((FunctionAddressRVA >= ExportDataDir.VirtualAddress) &&     //ExportDataDir [Start][Size]
					(FunctionAddressRVA < ExportDataDir.VirtualAddress + ExportDataDir.Size));

				if (isForwarded == FALSE)
				{
					UINT64  FunctionAddressVA;

					if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC) 
					{
						FunctionAddressVA = FunctionAddressRVA + pNtHeader->OptionalHeader32.ImageBase;
					}
					else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC) 
					{
						FunctionAddressVA = FunctionAddressRVA + pNtHeader->OptionalHeader64.ImageBase;
					}
					else 
					{
						ReleaseSource(pExportTableInfo);
						return FALSE;
					}
					EXPORT_TABLE v3;
					v3.FunctionIndex   = Base+Index;
					v3.FunctionAddress = FunctionAddressVA;
					v3.FuncitonName    = FunctionName;
					v3.ModuleName      = ModuleName;
					ExportList->push_back(v3);
					Index++;
				}	
			}
		}
		//按照序号导出
		if (NumberOfFunctions - NumberOfNames>0)
		{
			int i = 0;
			for (i = 0; i<NumberOfFunctions; i++)
			{
				if (bOk[i] == TRUE)
				{
					continue;
				}
				UINT32 v2 = (i * sizeof(UINT32));

				DWORD  FunctionAddressRVA;
				if (ReadDword(FunctionAddressTableSection.SectionInfo, FunctionAddressTableOffset + v2, &FunctionAddressRVA) == FALSE)
				{
					ReleaseSource(pExportTableInfo);
					return FALSE;
				}


				BOOL  isForwarded =
					((FunctionAddressRVA >= ExportDataDir.VirtualAddress) &&     //ExportDataDir [Start][Size]
					(FunctionAddressRVA < ExportDataDir.VirtualAddress + ExportDataDir.Size));

				if (isForwarded == FALSE)
				{
					UINT64  FunctionAddressVA;

					if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC) 
					{
						FunctionAddressVA = FunctionAddressRVA + pNtHeader->OptionalHeader32.ImageBase;
					}
					else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC) 
					{
						FunctionAddressVA = FunctionAddressRVA + pNtHeader->OptionalHeader64.ImageBase;
					}
					else {
						ReleaseSource(pExportTableInfo);
						return FALSE;
					}


					EXPORT_TABLE v3;

					v3.FunctionIndex   = Base + Index;
					v3.FunctionAddress = FunctionAddressVA;
					v3.FuncitonName    = "";
					v3.ModuleName      = ModuleName;
					ExportList->push_back(v3);

					Index ++;
				}

			}
			if (bOk != NULL)
			{
				delete bOk;
				bOk = NULL;
			}
		}
	}
	return TRUE;
}

//获得导入表
BOOL CPEParse::GetImportTable(PBUFFER_INFO pImportTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<IMPORT_TABLE>* ImportList)
{
	IMAGE_DATA_DIRECTORY   ImportDataDir;
	if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
	{
		ImportDataDir = pNtHeader->OptionalHeader32.DataDirectory[1];
	}
	else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
	{
		ImportDataDir = pNtHeader->OptionalHeader64.DataDirectory[1];
	}
	else
	{
		ReleaseSource(pImportTableInfo);
		return FALSE;
	}

	if (ImportDataDir.Size != 0)
	{
		UINT64 VirtualAddress;     //导入表绝对地址
		if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
		{
			VirtualAddress = ImportDataDir.VirtualAddress + pNtHeader->OptionalHeader32.ImageBase;
		}
		else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
		{
			VirtualAddress = ImportDataDir.VirtualAddress + pNtHeader->OptionalHeader64.ImageBase;
		}
		else
		{
			ReleaseSource(pImportTableInfo);
			return FALSE;
		}

		SECTION_TABLE  ImportDataDirSection = {};   //导出表所属的节
		if (GetSectionFromVA(SectionList, VirtualAddress, &ImportDataDirSection) == FALSE)
		{
			ReleaseSource(pImportTableInfo);
			return FALSE;
		}
		DWORD  ImportDataDirOffset = VirtualAddress - ImportDataDirSection.SectionBase;   //导出表绝对地址 -  所属节绝对地址  
		do
		{
			IMAGE_IMPORT_DESCRIPTOR  ImportDirTable;
			UINT32  v4 = 0;

			ReadDword(ImportDataDirSection.SectionInfo, ImportDataDirOffset + _offset(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk), &ImportDirTable.OriginalFirstThunk); //桥1
			ReadDword(ImportDataDirSection.SectionInfo, ImportDataDirOffset + _offset(IMAGE_IMPORT_DESCRIPTOR, TimeDateStamp), &ImportDirTable.TimeDateStamp);           //时间戳
			ReadDword(ImportDataDirSection.SectionInfo, ImportDataDirOffset + _offset(IMAGE_IMPORT_DESCRIPTOR, ForwarderChain), &ImportDirTable.ForwarderChain);         //链表的前一个结构
			ReadDword(ImportDataDirSection.SectionInfo, ImportDataDirOffset + _offset(IMAGE_IMPORT_DESCRIPTOR, Name), &ImportDirTable.Name);                             //指向链接库名字的指针
			ReadDword(ImportDataDirSection.SectionInfo, ImportDataDirOffset + _offset(IMAGE_IMPORT_DESCRIPTOR, FirstThunk), &ImportDirTable.FirstThunk);                 //桥2

			if (ImportDirTable.OriginalFirstThunk == 0 &&
				ImportDirTable.Name == 0 &&
				ImportDirTable.FirstThunk == 0)
			{
				break;
			}

			UINT64 ModuleNameVA = 0;
			if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
			{
				ModuleNameVA = ImportDirTable.Name + pNtHeader->OptionalHeader32.ImageBase;
			}
			else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
			{
				ModuleNameVA = ImportDirTable.Name + pNtHeader->OptionalHeader64.ImageBase;
			}
			else
			{
				ReleaseSource(pImportTableInfo);
				return FALSE;
			}

			SECTION_TABLE  ModuleNameSection;

			if (GetSectionFromVA(SectionList, ModuleNameVA, &ModuleNameSection) == FALSE)
			{
				ReleaseSource(pImportTableInfo);
				return FALSE;
			}
			UINT32  ModuleNameOffset = 0;
			ModuleNameOffset = ModuleNameVA - ModuleNameSection.SectionBase;  //获得Name在节中的相对偏移

																			  //获得导入模块名称
			BYTE   v1 = 0;
			std::string  ModuleName;
			do
			{
				if (ReadByte(ModuleNameSection.SectionInfo, ModuleNameOffset, &v1) == FALSE)
				{
					ReleaseSource(pImportTableInfo);
					return FALSE;
				}
				if (v1 == 0)    //ExportType.dll\0
				{
					break;
				}

				ModuleName.push_back(v1);
				ModuleNameOffset++;
			} while (true);

			//获得从该模块中导入函数  

			UINT64 ThunkVA = 0;

			if (ImportDirTable.OriginalFirstThunk != 0)
			{
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
				{
					ThunkVA = ImportDirTable.OriginalFirstThunk + pNtHeader->OptionalHeader32.ImageBase;
				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{
					ThunkVA = ImportDirTable.OriginalFirstThunk + pNtHeader->OptionalHeader64.ImageBase;
				}
				else
				{
					ReleaseSource(pImportTableInfo);
					return FALSE;
				}
			}
			else if (ImportDirTable.FirstThunk != 0)
			{
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
				{
					ThunkVA = ImportDirTable.FirstThunk + pNtHeader->OptionalHeader32.ImageBase;
				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{
					ThunkVA = ImportDirTable.FirstThunk + pNtHeader->OptionalHeader64.ImageBase;
				}
				else
				{
					ReleaseSource(pImportTableInfo);
					return FALSE;
				}
			}
			SECTION_TABLE  ThunkSection;
			if (GetSectionFromVA(SectionList, ThunkVA, &ThunkSection) == FALSE)
			{
				ReleaseSource(pImportTableInfo);
				return FALSE;
			}
			DWORD  ThunkOffset = 0;
			ThunkOffset = ThunkVA - ThunkSection.SectionBase;  //获得Name在节中的相对偏移
			do
			{
				UINT64 Ordinal = 0;
				UINT64 ThunkDataVA = 0;
				UINT8  Flag = 0;
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
				{
					DWORD  ThunkDataRVA = 0;

					if (ReadDword(ThunkSection.SectionInfo, ThunkOffset, &ThunkDataRVA) == FALSE) 
					{
						ReleaseSource(pImportTableInfo);
						return FALSE;
					}

					if (ThunkDataRVA == 0)
					{
						break;
					}
					//如果ThunkData 最高位是1 就是序号导入

					Flag = ThunkDataRVA >> 31;

					Ordinal = ThunkDataRVA << 1;
					Ordinal = Ordinal >> 1;

					ThunkDataVA = ThunkDataRVA + pNtHeader->OptionalHeader32.ImageBase;

				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{

					UINT64  ThunkDataRVA = 0;

					if (ReadQword(ThunkSection.SectionInfo, ThunkOffset, &ThunkDataRVA) == FALSE) 
					{
						ReleaseSource(pImportTableInfo);
						return FALSE;
					}

					if (ThunkDataRVA == 0)
					{
						break;
					}
					Flag = ThunkDataRVA >> 63;
					Ordinal = ThunkDataRVA << 1;
					Ordinal = Ordinal >> 1;
					ThunkDataVA = ThunkDataRVA + pNtHeader->OptionalHeader64.ImageBase;

				}
				else
				{
					ReleaseSource(pImportTableInfo);
					return FALSE;
				}
				if (Flag == 0)
				{
					std::string  FunctionName;
					SECTION_TABLE CurrentNameSection;

					if (GetSectionFromVA(SectionList, ThunkDataVA, &CurrentNameSection) == FALSE) 
					{
						ReleaseSource(pImportTableInfo);
						return FALSE;
					}

					UINT32  CurrentNameOffset = ThunkDataVA - CurrentNameSection.SectionBase;

					//导出函数的编号
					WORD  v2;
					if (ReadWord(CurrentNameSection.SectionInfo, CurrentNameOffset, &v2) == FALSE)
					{

						ReleaseSource(pImportTableInfo);
						return FALSE;
					}

					CurrentNameOffset += sizeof(WORD);
					do
					{
						BYTE v1;

						if (ReadByte(CurrentNameSection.SectionInfo, CurrentNameOffset, &v1) == FALSE)
						{
							ReleaseSource(pImportTableInfo);
							return FALSE;
						}

						if (v1 == 0)
						{
							//	 printf("%s\r\n",strFunctionName.data());
							break;
						}

						FunctionName.push_back(v1);
						CurrentNameOffset++;
					} while (true);
					IMPORT_TABLE v3;
					if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
					{
						v3.FunctionAddress = v4 + ImportDirTable.FirstThunk + pNtHeader->OptionalHeader32.ImageBase;

					}
					else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
					{
						v3.FunctionAddress = v4 + ImportDirTable.FirstThunk + pNtHeader->OptionalHeader64.ImageBase;
					}
					else
					{
						ReleaseSource(pImportTableInfo);
						return FALSE;
					}
					v3.FuncitonName = FunctionName;
					v3.ModuleName   = ModuleName;
					ImportList->push_back(v3);

				}
				else  //序号导入
				{
					char szOrdinal[0x20] = { 0 };
					sprintf_s(szOrdinal, 0x20, "%X", Ordinal);

					std::string      FunctionName =
						"ORDINAL_" + ModuleName + "_" + szOrdinal;

					IMPORT_TABLE v3;;

					if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
					{
						v3.FunctionAddress = v4 + ImportDirTable.FirstThunk + pNtHeader->OptionalHeader32.ImageBase;

					}
					else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
					{
						v3.FunctionAddress = v4 + ImportDirTable.FirstThunk + pNtHeader->OptionalHeader64.ImageBase;
					}
					else
					{
						ReleaseSource(pImportTableInfo);
						return FALSE;
					}

					v3.FuncitonName = FunctionName;
					v3.ModuleName   = ModuleName;
					ImportList->push_back(v3);
				}
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
				{
					ThunkOffset += sizeof(UINT32);
					v4 += sizeof(UINT32);

				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{
					ThunkOffset += sizeof(UINT64);
					v4 += sizeof(UINT64);

				}
				else
				{
					ReleaseSource(pImportTableInfo);
					return FALSE;
				}
			} while (true);
		ImportDataDirOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}while (true);
	}
	return TRUE;
}

//获得重定向表
BOOL CPEParse::GetBaseRelocTable(PBUFFER_INFO pBaseRelocTableInfo, PNT_HEADER pNtHeader, std::list<SECTION_TABLE>* SectionList, std::list<BASERELOC_TABLE>* BaseRelocList)
{
	//重定向表
	IMAGE_DATA_DIRECTORY   BaseRelocDataDir;
	if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
	{
		BaseRelocDataDir = pNtHeader->OptionalHeader32.DataDirectory[5];
	}
	else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
	{
		BaseRelocDataDir = pNtHeader->OptionalHeader64.DataDirectory[5];
	}
	else
	{
		ReleaseSource(pBaseRelocTableInfo);
		return FALSE;
	}

	if (BaseRelocDataDir.Size != 0)
	{
		UINT64 VirtualAddress;     //重定向表绝对地址
		if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC)
		{
			VirtualAddress = BaseRelocDataDir.VirtualAddress + pNtHeader->OptionalHeader32.ImageBase;
		}
		else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
		{
			VirtualAddress = BaseRelocDataDir.VirtualAddress + pNtHeader->OptionalHeader64.ImageBase;
		}
		else
		{
			ReleaseSource(pBaseRelocTableInfo);
			return FALSE;
		}
		SECTION_TABLE  BaseRelocDataDirSection;   //导出表所属的节
		if (GetSectionFromVA(SectionList, VirtualAddress, &BaseRelocDataDirSection) == FALSE)
		{
			ReleaseSource(pBaseRelocTableInfo);
			return FALSE;
		}
		
		DWORD  BaseRelocDataDirOffset = VirtualAddress - BaseRelocDataDirSection.SectionBase;
		do
		{
			//读VirtualAddress SizeOfBlock
			DWORD  VirtualAddress;
			DWORD  SizeOfBlock;
			if (ReadDword(BaseRelocDataDirSection.SectionInfo,
				BaseRelocDataDirOffset + _offset(IMAGE_BASE_RELOCATION, VirtualAddress),
				&VirtualAddress) == FALSE)
			{
				ReleaseSource(pBaseRelocTableInfo);
				return FALSE;
			}
			if (ReadDword(BaseRelocDataDirSection.SectionInfo,
				BaseRelocDataDirOffset + _offset(IMAGE_BASE_RELOCATION, SizeOfBlock),
				&SizeOfBlock) == FALSE)
			{
				ReleaseSource(pBaseRelocTableInfo);
				return FALSE;
			}

			DWORD  BlockCount = (SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD   ItemOffset = 0;
			while (BlockCount != 0)
			{
				WORD	   Block;
				BYTE       Type4;
				WORD       Offset12;

				if (ReadWord(BaseRelocDataDirSection.SectionInfo, ItemOffset + BaseRelocDataDirOffset + sizeof(IMAGE_BASE_RELOCATION), &Block) == FALSE)
				{
					ReleaseSource(pBaseRelocTableInfo);
					return FALSE;
				}
				Type4 = Block >> 12;
				Offset12 = Block & ~0xf000;       //偏移


				DWORD  BaseRelocVA;
				if (pNtHeader->Magic == NT_OPTIONAL_32_MAGIC) 
				{
					BaseRelocVA = VirtualAddress + Offset12; //+ ParsedPE->PEHeader.NtHeader.OptionalHeader32.ImageBase;
				}
				else if (pNtHeader->Magic == NT_OPTIONAL_64_MAGIC)
				{
					BaseRelocVA = VirtualAddress + Offset12; //+ ParsedPE->PEHeader.NtHeader.OptionalHeader64.ImageBase;
				}
				else
				{
					ReleaseSource(pBaseRelocTableInfo);
					return FALSE;
				}

				BASERELOC_TABLE v1;

				v1.ItemAddress = BaseRelocVA;
				v1.Type = (RELOC_TYPE)Type4;
				v1.AddressRVA = VirtualAddress;
				v1.BlockSize = SizeOfBlock;
				BaseRelocList->push_back(v1);

				BlockCount--;

				ItemOffset += sizeof(WORD);

			}
			BaseRelocDataDirOffset += SizeOfBlock;
		} while (true);
		BaseRelocDataDirOffset += sizeof(IMAGE_BASE_RELOCATION);
	}
	return TRUE;
}

//根据绝对地址获得节
BOOL CPEParse::GetSectionFromVA(std::list<SECTION_TABLE>* SectionList, UINT64 VirtualAddress, SECTION_TABLE* Section)
{
	for (std::list<SECTION_TABLE>::iterator it = SectionList->begin(); it != SectionList->end(); ++it)
	{
		SECTION_TABLE v1 = *it;

		UINT64 SectionStart = v1.SectionBase;
		UINT64 SectionEnd = SectionStart + v1.SectionHeader.Misc.VirtualSize;
		if (VirtualAddress >= SectionStart&&VirtualAddress <= SectionEnd)
		{
			*Section = v1;
			return TRUE;
		}
	}
	return FALSE;
}