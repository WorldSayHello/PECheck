// Export.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "Export.h"
#include "afxdialogex.h"


// CExport �Ի���

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


// CExport ��Ϣ�������


BOOL CExport::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	m_ExportList.InsertColumn(0, L"ģ������", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(1, L"�������", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(2, L"��������", LVCFMT_LEFT, 150);
	m_ExportList.InsertColumn(3, L"������ַ", LVCFMT_LEFT, 150);
	m_ExportList.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
