// Resources.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "Resources.h"
#include "afxdialogex.h"


// CResources �Ի���

IMPLEMENT_DYNAMIC(CResources, CDialogEx)

CResources::CResources(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_RESOURCES, pParent)
{

}

CResources::~CResources()
{
}

void CResources::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE1, m_SectionTree);
}


BEGIN_MESSAGE_MAP(CResources, CDialogEx)
END_MESSAGE_MAP()


// CResources ��Ϣ�������
