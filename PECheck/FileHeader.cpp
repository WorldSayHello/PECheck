// FileHeader.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "FileHeader.h"
#include "afxdialogex.h"


// CFileHeader �Ի���

IMPLEMENT_DYNAMIC(CFileHeader, CDialogEx)

CFileHeader::CFileHeader(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_FILE_HEADER, pParent)
{

}

CFileHeader::~CFileHeader()
{
}

void CFileHeader::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CFileHeader, CDialogEx)
END_MESSAGE_MAP()


// CFileHeader ��Ϣ�������
