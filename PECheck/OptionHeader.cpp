// OptionHeader.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "OptionHeader.h"
#include "afxdialogex.h"


// COptionHeader �Ի���

IMPLEMENT_DYNAMIC(COptionHeader, CDialogEx)

COptionHeader::COptionHeader(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_OPTION_HEADER, pParent)
{

}

COptionHeader::~COptionHeader()
{
}

void COptionHeader::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(COptionHeader, CDialogEx)
END_MESSAGE_MAP()


// COptionHeader ��Ϣ�������


BOOL COptionHeader::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
