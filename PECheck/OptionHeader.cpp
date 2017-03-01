// OptionHeader.cpp : 实现文件
//

#include "stdafx.h"
#include "PECheck.h"
#include "OptionHeader.h"
#include "afxdialogex.h"


// COptionHeader 对话框

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


// COptionHeader 消息处理程序


BOOL COptionHeader::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
