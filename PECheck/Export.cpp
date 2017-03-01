// Export.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "Export.h"
#include "afxdialogex.h"


// CExport 对话框

IMPLEMENT_DYNAMIC(CExport, CDialogEx)

CExport::CExport(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_EXPORT, pParent)
{

}

CExport::~CExport()
{
}

void CExport::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_EXPORT, m_ExportList);
}


BEGIN_MESSAGE_MAP(CExport, CDialogEx)
END_MESSAGE_MAP()


// CExport 消息处理程序


BOOL CExport::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	m_ExportList.InsertColumn(0, L"模块名称", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(1, L"函数序号", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(2, L"函数名称", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(3, L"函数地址", LVCFMT_LEFT, 150);
	m_ExportList.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
