// BaseReloc.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "BaseReloc.h"
#include "afxdialogex.h"


// CBaseReloc �Ի���

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


// CBaseReloc ��Ϣ�������


BOOL CBaseReloc::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	m_BaseRelocList.InsertColumn(0, L"���Ե�ַ", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(1, L"���ƫ��", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(2, L"���С", LVCFMT_LEFT, 150);
	m_BaseRelocList.InsertColumn(3, L"����", LVCFMT_LEFT, 150);
	m_BaseRelocList.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
