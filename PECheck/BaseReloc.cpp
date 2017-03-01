// BaseReloc.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "BaseReloc.h"
#include "afxdialogex.h"


// CBaseReloc 对话框

IMPLEMENT_DYNAMIC(CBaseReloc, CDialogEx)

CBaseReloc::CBaseReloc(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_BASE_RELC, pParent)
{

}

CBaseReloc::~CBaseReloc()
{
}

void CBaseReloc::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_BASE_RELC, m_BaseRelocList);
}


BEGIN_MESSAGE_MAP(CBaseReloc, CDialogEx)
END_MESSAGE_MAP()


// CBaseReloc 消息处理程序


BOOL CBaseReloc::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	m_BaseRelocList.InsertColumn(0, L"绝对地址", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(1, L"相对偏移", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(2, L"块大小", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(3, L"类型", LVCFMT_LEFT, 150);
	m_BaseRelocList.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
