// FileHeader.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "FileHeader.h"
#include "afxdialogex.h"


// CFileHeader 对话框

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


// CFileHeader 消息处理程序
