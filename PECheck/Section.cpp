// Section.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "Section.h"
#include "afxdialogex.h"


// CSection 对话框

IMPLEMENT_DYNAMIC(CSection, CDialogEx)

CSection::CSection(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_SECTION, pParent)
{

}

CSection::~CSection()
{
}

void CSection::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SECTION, m_SectionList);
}


BEGIN_MESSAGE_MAP(CSection, CDialogEx)
END_MESSAGE_MAP()


// CSection 消息处理程序


BOOL CSection::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	m_SectionList.InsertColumn(0, L"名称", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(1, L"内存中地址", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(2, L"内存中大小", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(3, L"文件中地址", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(4, L"文件中大小", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(5, L"标志", LVCFMT_LEFT, 100);
	
	m_SectionList.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
