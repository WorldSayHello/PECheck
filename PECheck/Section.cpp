// Section.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "Section.h"
#include "afxdialogex.h"


// CSection �Ի���

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


// CSection ��Ϣ�������


BOOL CSection::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	m_SectionList.InsertColumn(0, L"����", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(1, L"�ڴ��е�ַ", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(2, L"�ڴ��д�С", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(3, L"�ļ��е�ַ", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(4, L"�ļ��д�С", LVCFMT_LEFT, 100);
	m_SectionList.InsertColumn(5, L"��־", LVCFMT_LEFT, 100);
	
	m_SectionList.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	
	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
