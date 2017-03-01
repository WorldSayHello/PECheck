// Import.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "Import.h"
#include "afxdialogex.h"


// CImport 对话框

IMPLEMENT_DYNAMIC(CImport, CDialogEx)

CImport::CImport(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_IMPORT, pParent)
{
}

CImport::~CImport()
{
}

void CImport::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_IMPORT, m_ImportList);
}


BEGIN_MESSAGE_MAP(CImport, CDialogEx)
END_MESSAGE_MAP()


// CImport 消息处理程序


BOOL CImport::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	m_ImportList.InsertColumn(0, L"模块名称", LVCFMT_LEFT,200);
	m_ImportList.InsertColumn(1, L"函数名称", LVCFMT_LEFT,200);
	m_ImportList.InsertColumn(2, L"函数地址", LVCFMT_LEFT,200);
	m_ImportList.SetExtendedStyle(LVS_EX_FULLROWSELECT);


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
