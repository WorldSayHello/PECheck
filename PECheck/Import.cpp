// Import.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "Import.h"
#include "afxdialogex.h"


// CImport �Ի���

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


// CImport ��Ϣ�������


BOOL CImport::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��

	m_ImportList.InsertColumn(0, L"ģ������", LVCFMT_LEFT,200);
	m_ImportList.InsertColumn(1, L"��������", LVCFMT_LEFT,200);
	m_ImportList.InsertColumn(2, L"������ַ", LVCFMT_LEFT,200);
	m_ImportList.SetExtendedStyle(LVS_EX_FULLROWSELECT);


	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
