
// PECheckDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "PECheckDlg.h"
#include "afxdialogex.h"
#include "PEParse.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPECheckDlg 对话框



CPECheckDlg::CPECheckDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_PECHECK_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPECheckDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB_MENU, m_tMenu);
}

BEGIN_MESSAGE_MAP(CPECheckDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_MENU, &CPECheckDlg::OnTcnSelchangeTabMenu)
	ON_MESSAGE(WM_START_PARSE_PE, &CPECheckDlg::OnStartParsePe)
	ON_MESSAGE(WM_END_PARSE_PE, &CPECheckDlg::OnEndParsePe)
	ON_WM_SIZE()
END_MESSAGE_MAP()


// CPECheckDlg 消息处理程序

BOOL CPECheckDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_tMenu.InsertItem(0, L"主页");
	m_tMenu.InsertItem(1, L"DOS头");
	m_tMenu.InsertItem(2, L"PE标准头");
	m_tMenu.InsertItem(3, L"PE扩展头");
	m_tMenu.InsertItem(4, L"资源表");
	m_tMenu.InsertItem(5, L"节表");
	m_tMenu.InsertItem(6, L"导入表");
	m_tMenu.InsertItem(7, L"导出表");
	m_tMenu.InsertItem(8, L"重定向表");

	m_MainPage.Create(IDD_DIALOG_MAINPAGE, GetDlgItem(IDC_TAB_MENU));
	m_MainPage.SetParent(GetDlgItem(IDC_TAB_MENU));

	m_tMenu.GetClientRect(&m_rect);
	m_rect.top += 22;
	m_rect.bottom -= 0;
	m_rect.left += 1;
	m_rect.right -= 2;
	m_MainPage.MoveWindow(&m_rect);
	m_MainPage.ShowWindow(true);

	m_DosHeader.Create(IDD_DIALOG_DOS_HEADER,GetDlgItem(IDC_TAB_MENU));
	m_DosHeader.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_DosHeader.MoveWindow(&m_rect);
	m_DosHeader.ShowWindow(false);

	m_FileHeader.Create(IDD_DIALOG_FILE_HEADER, GetDlgItem(IDC_TAB_MENU));
	m_FileHeader.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_FileHeader.MoveWindow(&m_rect);
	m_FileHeader.ShowWindow(false);
	
	m_OptionHeader.Create(IDD_DIALOG_OPTION_HEADER, GetDlgItem(IDC_TAB_MENU));
	m_OptionHeader.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_OptionHeader.MoveWindow(&m_rect);
	m_OptionHeader.ShowWindow(false);

	m_Resources.Create(IDD_DIALOG_RESOURCES, GetDlgItem(IDC_TAB_MENU));
	m_Resources.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_Resources.MoveWindow(&m_rect);
	m_Resources.ShowWindow(false);

	m_Section.Create(IDD_DIALOG_SECTION, GetDlgItem(IDC_TAB_MENU));
	m_Section.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_Section.MoveWindow(&m_rect);
	m_Section.ShowWindow(false);
	
	m_Import.Create(IDD_DIALOG_IMPORT, GetDlgItem(IDC_TAB_MENU));
	m_Import.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_Import.MoveWindow(&m_rect);
	m_Import.ShowWindow(false);

	m_Export.Create(IDD_DIALOG_EXPORT, GetDlgItem(IDC_TAB_MENU));
	m_Export.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_Export.MoveWindow(&m_rect);
	m_Export.ShowWindow(false);

	m_BaseReloc.Create(IDD_DIALOG_BASE_RELC, GetDlgItem(IDC_TAB_MENU));
	m_BaseReloc.SetParent(GetDlgItem(IDC_TAB_MENU));
	m_BaseReloc.MoveWindow(&m_rect);
	m_BaseReloc.ShowWindow(false);

	m_tMenu.SetCurSel(0);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPECheckDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPECheckDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CPECheckDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CPECheckDlg::OnTcnSelchangeTabMenu(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码
	int CurSel = m_tMenu.GetCurSel();
	switch (CurSel)
	{
	case 0:
		m_MainPage.ShowWindow(true);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break;
	case 1:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(true);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break;
	case 2:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(true);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break;
	case 3:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(true);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break; 
	case 4:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(true);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break;
	case 5:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(true);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break; 
	case 6:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(true);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(false);
		break;
	case 7:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(true);
		m_BaseReloc.ShowWindow(false);
		break;
	case 8:
		m_MainPage.ShowWindow(false);
		m_DosHeader.ShowWindow(false);
		m_FileHeader.ShowWindow(false);
		m_OptionHeader.ShowWindow(false);
		m_Section.ShowWindow(false);
		m_Resources.ShowWindow(false);
		m_Import.ShowWindow(false);
		m_Export.ShowWindow(false);
		m_BaseReloc.ShowWindow(true);
		break;
	default:
		break;
	}


	*pResult = 0;
}


LRESULT CPECheckDlg::OnStartParsePe(WPARAM wParam, LPARAM lParam)
{
	CPEParse* PEParse = new CPEParse();
	m_wszFilePath = (LPWSTR)(LPCWSTR)m_MainPage.m_FilePath;
	m_pParsedPE = new PARSED_PE;
	m_pParsedPE->pPEDataInfo = new BUFFER_INFO;
	ZeroMemory(m_pParsedPE->pPEDataInfo, sizeof(BUFFER_INFO));
	PBUFFER_INFO pRemainingData = NULL;
	if (!PEParse->GetFileInfo(m_wszFilePath))
	{
		MessageBox(L"读取文件信息失败!");
		return -1;
	}
	//设置主页面信息
	CString v1;
	v1.Format(L"0x%X", PEParse->m_PeInfo.FileSize);
	m_MainPage.SetDlgItemText(IDC_EDIT_SIZE, v1);
	m_MainPage.SetDlgItemText(IDC_EDIT_ATTRIBUTE, PEParse->m_PeInfo.Attribute);
	m_MainPage.SetDlgItemText(IDC_EDIT_CREATE_DATE, PEParse->m_PeInfo.CreatTime);
	m_MainPage.SetDlgItemText(IDC_EDIT_ALTER_DATE, PEParse->m_PeInfo.AccessTime);
	m_MainPage.SetDlgItemText(IDC_EDIT_VISIT_DATA, PEParse->m_PeInfo.ModifyTime);

	if (PEParse->ReadFileToBuffer(m_wszFilePath, m_pParsedPE->pPEDataInfo))
	{
		if (!PEParse->GetDosHeader(m_pParsedPE->pPEDataInfo, &m_pParsedPE->DosHeader, &pRemainingData))
		{
			MessageBox(L"读取Dos头失败!");
			return -1;
		}
		v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_magic);
		m_MainPage.SetDlgItemText(IDC_EDIT_SIGNATURE, v1);
		SetDosEdit();

		if (!PEParse->GetNtHeader(pRemainingData,&m_pParsedPE->NtHeader, &pRemainingData))
		{
			MessageBox(L"读取PE头失败!");
			return -1;
		}
		SetFileEdit();
		if (m_pParsedPE->NtHeader.Magic==0x10b)
		{
			SetOptionEdit32();
		}
		else
		{
			SetOptionEdit64();
		}
		m_pParsedPE->pTable = new PARSED_PE_TABLE();
		//节表
		if (PEParse->GetSections(pRemainingData, m_pParsedPE->pPEDataInfo, &m_pParsedPE->NtHeader, &m_pParsedPE->pTable->SectionList))
		{
			SetSectionList();
		}	
		//资源表
		if (PEParse->GetResources(pRemainingData,m_pParsedPE->pPEDataInfo,&m_pParsedPE->pTable->SectionList,&m_pParsedPE->pTable->ResourcesList, &m_Resources))
		{
			SetResourcesList();
		}
		//导出表
		if (PEParse->GetExportTable(pRemainingData, &m_pParsedPE->NtHeader, &m_pParsedPE->pTable->SectionList, &m_pParsedPE->pTable->ExportList))
		{
			SetExportList();
		}
		//导入表
		if (PEParse->GetImportTable(pRemainingData, &m_pParsedPE->NtHeader, &m_pParsedPE->pTable->SectionList, &m_pParsedPE->pTable->ImportList))
		{
			SetImportList();
		}
		//重定向表
		if (PEParse->GetBaseRelocTable(pRemainingData, &m_pParsedPE->NtHeader, &m_pParsedPE->pTable->SectionList, &m_pParsedPE->pTable->BaseRelocList))
		{
			SetBaseRelocList();
		}	
	}


	return 0;
}


afx_msg LRESULT CPECheckDlg::OnEndParsePe(WPARAM wParam, LPARAM lParam)
{
	
	return 0;
}

void CPECheckDlg::SetDosEdit()
{
	CString v1;
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_magic);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_MAGIC, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_cblp);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CBLP, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_cp);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CP, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_crlc);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CRLC, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_cparhdr);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CPARHDR, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_minalloc);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_MINALLOC, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_maxalloc);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_MAXALLOC, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_ss);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_SS, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_sp);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_SP, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_csum);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CSUM, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_ip);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_IP, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_cs);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_CS, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_lfarlc);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_LFARLC, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_ovno);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_OVNO, v1);
	for (int i = 0; i < 4; i++) {
		CString v2;
		v2.Format(L"%X", m_pParsedPE->DosHeader.e_res[i]);
		v1 += v2;
	}
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_RES, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_oemid);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_OEMID, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_oeminfo);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_OEMINFO, v1);
	for (int i = 0; i < 10; i++) {
		CString v2;
		v2.Format(L"%X", m_pParsedPE->DosHeader.e_res2[i]);
		v1 += v2;
	}
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_RES2, v1);
	v1.Format(L"0x%X", m_pParsedPE->DosHeader.e_lfanew);
	m_DosHeader.SetDlgItemText(IDC_EDIT_E_LFANEW, v1);
}

void CPECheckDlg::SetFileEdit()
{
	CString v1;
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.Signature);
	m_FileHeader.SetDlgItemText(IDC_EDIT_SIGNATURE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.Machine);
	m_FileHeader.SetDlgItemText(IDC_EDIT_MACHINE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.NumberOfSections);
	m_FileHeader.SetDlgItemText(IDC_EDIT_NUM_OF_SEC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.TimeDateStamp);
	m_FileHeader.SetDlgItemText(IDC_EDIT_TIME_DATE_STAMP, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.PointerToSymbolTable);
	m_FileHeader.SetDlgItemText(IDC_EDIT_POINTER_TO_SYMBOL, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.NumberOfSymbols);
	m_FileHeader.SetDlgItemText(IDC_EDIT_NUM_OF_SYMBOL, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.SizeOfOptionalHeader);
	m_FileHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_OPT_HEADER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.FileHeader.Characteristics);
	m_FileHeader.SetDlgItemText(IDC_EDIT_CHARACT, v1);
}


void CPECheckDlg::SetOptionEdit32()
{
	CString v1;
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.Magic);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAGIC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MajorLinkerVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_LIN_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MinorLinkerVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_LIN_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfCode);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_CODE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfInitializedData);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_INIT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfUninitializedData);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_UNINIT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.AddressOfEntryPoint);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_ENTRY_POINT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.BaseOfCode);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_BASE_OF_CODE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.BaseOfData);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_BASE_OF_DATA, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.ImageBase);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_IMAGE_BASE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SectionAlignment);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SECTION_ALIGN, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.FileAlignment);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_FILE_ALOGN, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MajorOperatingSystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJOR_OS_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MinorOperatingSystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_OS_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MajorImageVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_IMAG_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MinorImageVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_IMAG_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MajorSubsystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_SUB_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.MinorSubsystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_SUB_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.Win32VersionValue);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_WIN_VER_VAL, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfImage);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_IMAG, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfHeaders);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HEADER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.CheckSum);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_CHECK_SUM, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.Subsystem);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SUB, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.DllCharacteristics);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_DLL_CHARACT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfStackReserve);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_SR, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfStackCommit);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_SC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfHeapReserve);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HR, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.SizeOfHeapCommit);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.LoaderFlags);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_LODER_FLAGS, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader32.NumberOfRvaAndSizes);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_NUM_OF_RVA, v1);
}


void CPECheckDlg::SetOptionEdit64()
{
	CString v1;
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.Magic);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAGIC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MajorLinkerVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_LIN_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MinorLinkerVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_LIN_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfCode);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_CODE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfInitializedData);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_INIT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfUninitializedData);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_UNINIT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.AddressOfEntryPoint);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_ENTRY_POINT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.BaseOfCode);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_BASE_OF_CODE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.ImageBase);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_IMAGE_BASE, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SectionAlignment);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SECTION_ALIGN, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.FileAlignment);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_FILE_ALOGN, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MajorOperatingSystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJOR_OS_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MinorOperatingSystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_OS_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MajorImageVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_IMAG_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MinorImageVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_IMAG_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MajorSubsystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MAJ_SUB_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.MinorSubsystemVersion);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_MIN_SUB_VER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.Win32VersionValue);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_WIN_VER_VAL, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfImage);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_IMAG, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfHeaders);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HEADER, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.CheckSum);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_CHECK_SUM, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.Subsystem);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SUB, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.DllCharacteristics);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_DLL_CHARACT, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfStackReserve);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_SR, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfStackCommit);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_SC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfHeapReserve);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HR, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.SizeOfHeapCommit);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_SIZE_OF_HC, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.LoaderFlags);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_LODER_FLAGS, v1);
	v1.Format(L"0x%X", m_pParsedPE->NtHeader.OptionalHeader64.NumberOfRvaAndSizes);
	m_OptionHeader.SetDlgItemText(IDC_EDIT_NUM_OF_RVA, v1);
}


void CPECheckDlg::SetSectionList()
{
	m_Section.m_SectionList.DeleteAllItems();
	std::list<SECTION_TABLE>::iterator Section;
	int i = 0;
	for (Section= m_pParsedPE->pTable->SectionList.begin();Section!= m_pParsedPE->pTable->SectionList.end();++Section)
	{
		CString v1;
		v1.Format(L"%S", Section->SectionName.c_str());
		m_Section.m_SectionList.InsertItem(i, v1);
		v1.Format(L"0x%X", Section->SectionBase);
		m_Section.m_SectionList.SetItemText(i, 1, v1);
		v1.Format(L"0x%X", Section->SectionHeader.Misc.VirtualSize);
		m_Section.m_SectionList.SetItemText(i, 2, v1);
		v1.Format(L"0x%X", Section->SectionHeader.PointerToRawData);
		m_Section.m_SectionList.SetItemText(i, 3, v1);
		v1.Format(L"0x%X", Section->SectionHeader.SizeOfRawData);
		m_Section.m_SectionList.SetItemText(i, 4, v1);
		v1.Format(L"0x%X", Section->SectionHeader.Characteristics);
		m_Section.m_SectionList.SetItemText(i, 5, v1);
		i++;
	}	
}


void CPECheckDlg::SetResourcesList()
{
	
	std::list<RESOURCES_TABLE>::iterator Resources;
	int i = 0;
	/*for (Resources = m_pParsedPE->pTable->ResourcesList.begin(); Resources != m_pParsedPE->pTable->ResourcesList.end(); ++Resources)
	{
		CString v1;
		v1.Format(L"%s", Resources->FirstID.c_str());
		m_Resources.m_hRoot = m_Resources.m_SectionTree.InsertItem(v1, TVI_ROOT, TVI_LAST);
		v1.Format(L"Id:%s", Resources->SecondID.c_str());
		m_Resources.m_hSecondItem = m_Resources.m_SectionTree.InsertItem(v1, 1, i, m_Resources.m_hRoot, TVI_LAST);
		v1.Format(L"Id:%s", Resources->ThirdID.c_str());
		m_Resources.m_hThirdItem = m_Resources.m_SectionTree.InsertItem(v1, 1, i, m_Resources.m_hSecondItem, TVI_LAST);
		i++;
	}*/
	//m_Resources.m_hRoot = m_Resources.m_SectionTree.InsertItem(m_pParsedPE->pTable->ResourcesList,TVI_ROOT,TVI_LAST);
	//m_Resources.m_hCataItem = m_Resources.m_SectionTree.InsertItem(L"根2", 1, 1, m_Resources.m_hRoot, TVI_LAST);
	//m_Resources.m_SectionTree.SetItemData(m_Resources.m_hCataItem, 1);
	//m_Resources.m_SectionTree.InsertItem(L"根3", TVI_ROOT, TVI_LAST);
}

//设置导出表
void CPECheckDlg::SetExportList()
{
	m_Export.m_ExportList.DeleteAllItems();
	std::list<EXPORT_TABLE>::iterator Export;
	int i = 0;
	for (Export = m_pParsedPE->pTable->ExportList.begin(); Export != m_pParsedPE->pTable->ExportList.end(); ++Export)
	{
		CString v1;
		v1.Format(L"%S", Export->ModuleName.c_str());
		m_Export.m_ExportList.InsertItem(i, v1);
		v1.Format(L"%d", Export->FunctionIndex);
		m_Export.m_ExportList.SetItemText(i, 1, v1);
		v1.Format(L"%S", Export->FuncitonName.c_str());
		m_Export.m_ExportList.SetItemText(i, 2, v1);
		v1.Format(L"0x%X", Export->FunctionAddress);
		m_Export.m_ExportList.SetItemText(i, 3, v1);
		i++;
	}
	//设置最后一行为空
	m_Export.m_ExportList.InsertItem(m_Export.m_ExportList.GetItemCount(), L"");
	m_Export.m_ExportList.SetItemText(m_Export.m_ExportList.GetItemCount(), 1, L"");
	m_Export.m_ExportList.SetItemText(m_Export.m_ExportList.GetItemCount(), 2, L"");
	m_Export.m_ExportList.SetItemText(m_Export.m_ExportList.GetItemCount(), 3, L"");
}
//设置导入表
void CPECheckDlg::SetImportList()
{
	m_Import.m_ImportList.DeleteAllItems();
	std::list<IMPORT_TABLE>::iterator Import;
	int i = 0;
	for (Import = m_pParsedPE->pTable->ImportList.begin(); Import != m_pParsedPE->pTable->ImportList.end(); ++Import)
	{
		CString v1;
		v1.Format(L"%S", Import->ModuleName.c_str());
		m_Import.m_ImportList.InsertItem(i, v1);
		v1.Format(L"%S", Import->FuncitonName.c_str());
		m_Import.m_ImportList.SetItemText(i, 1, v1);
		v1.Format(L"0x%X", Import->FunctionAddress);
		m_Import.m_ImportList.SetItemText(i, 2, v1);
		i++;
	}
	//设置最后一行为空
	m_Import.m_ImportList.InsertItem(m_Import.m_ImportList.GetItemCount(), L"");
	m_Import.m_ImportList.SetItemText(m_Import.m_ImportList.GetItemCount(), 1, L"");
	m_Import.m_ImportList.SetItemText(m_Import.m_ImportList.GetItemCount(), 2, L"");
}
//设置重定位表
void CPECheckDlg::SetBaseRelocList()
{
	m_BaseReloc.m_BaseRelocList.DeleteAllItems();
	std::list<BASERELOC_TABLE>::iterator BaseReloc;
	int i = 0;
	for (BaseReloc = m_pParsedPE->pTable->BaseRelocList.begin(); BaseReloc != m_pParsedPE->pTable->BaseRelocList.end(); ++BaseReloc)
	{
		CString v1;
		v1.Format(L"0x%X", BaseReloc->ItemAddress);
		m_BaseReloc.m_BaseRelocList.InsertItem(i, v1);
		v1.Format(L"0x%x", BaseReloc->AddressRVA);
		m_BaseReloc.m_BaseRelocList.SetItemText(i, 1, v1);
		v1.Format(L"0x%X", BaseReloc->BlockSize);
		m_BaseReloc.m_BaseRelocList.SetItemText(i, 2, v1);
		v1.Format(L"%X", BaseReloc->Type);
		m_BaseReloc.m_BaseRelocList.SetItemText(i, 3, v1);
		i++;
	}
	//设置最后一行为空
	m_BaseReloc.m_BaseRelocList.InsertItem(m_BaseReloc.m_BaseRelocList.GetItemCount(), L"");
	m_BaseReloc.m_BaseRelocList.SetItemText(m_BaseReloc.m_BaseRelocList.GetItemCount(), 1, L"");
	m_BaseReloc.m_BaseRelocList.SetItemText(m_BaseReloc.m_BaseRelocList.GetItemCount(), 2, L"");
}

void CPECheckDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);
	
	// TODO: 在此处添加消息处理程序代码
	CWnd *pWnd; 
	pWnd = GetDlgItem(IDC_TAB_MENU); //获取控件句柄
	if (pWnd && nType != 1)//判断是否为空，因为对话框创建时会调用此函数，而当时控件还未创建
	{
		
		CRect rect; //获取控件变化前大小
		pWnd->GetWindowRect(&rect); ScreenToClient(&rect);//将控件大小转换为在对话框中的区域坐标
														  // cx/m_rect.Width()为对话框在横向的变化比例
		rect.left = rect.left*cx / m_rect.Width();/////调整控件大小
		rect.right = rect.right*cx / m_rect.Width();
		rect.top = rect.top*cy / m_rect.Height();
		rect.bottom = rect.bottom*cy / m_rect.Height();
		pWnd->MoveWindow(rect);//设置控件大小
	} 
	GetClientRect(&m_rect);//将变化后的对话框大小设为旧大小
}

