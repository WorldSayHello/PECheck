// DosHeader.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "DosHeader.h"
#include "afxdialogex.h"


// CDosHeader �Ի���

IMPLEMENT_DYNAMIC(CDosHeader, CDialogEx)

CDosHeader::CDosHeader(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_DOS_HEADER, pParent)
{

}

CDosHeader::~CDosHeader()
{
}

void CDosHeader::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDosHeader, CDialogEx)
END_MESSAGE_MAP()


// CDosHeader ��Ϣ�������
