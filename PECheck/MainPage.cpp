// MainPage.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "PECheck.h"
#include "MainPage.h"
#include "afxdialogex.h"
#include "PEParse.h"
#include "Common.h"

// CMainPage �Ի���

IMPLEMENT_DYNAMIC(CMainPage, CDialogEx)

CMainPage::CMainPage(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_MAINPAGE, pParent)
	, m_FilePath(_T(""))
{

}

CMainPage::~CMainPage()
{
}

void CMainPage::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_FILE_PATH, m_epFilePath);
}


BEGIN_MESSAGE_MAP(CMainPage, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON_OPEN_FILE, &CMainPage::OnBnClickedButtonOpenFile)
	ON_BN_CLICKED(IDC_BUTTON_CLOSE_FILE, &CMainPage::OnBnClickedButtonCloseFile)
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONDOWN()
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()


// CMainPage ��Ϣ�������


void CMainPage::OnBnClickedButtonOpenFile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	m_epFilePath.GetWindowText(m_FilePath);
	if (m_FilePath.IsEmpty())
	{
		return;
	}
	//��ǰ���ڵĸ�������teb�ؼ���teb�ؼ��ĸ����ڲ���������
	GetParent()->GetParent()->SendMessage(WM_START_PARSE_PE);
}



void CMainPage::OnBnClickedButtonCloseFile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//���ؼ������ÿգ�Ȼ����Ϣ��������
	SetDlgItemText(IDC_EDIT_FILE_PATH, L"");
	SetDlgItemText(IDC_EDIT_SIGNATURE, L"");
	SetDlgItemText(IDC_EDIT_SIZE, L"");
	SetDlgItemText(IDC_EDIT_ATTRIBUTE, L"");
	SetDlgItemText(IDC_EDIT_CREATE_DATE, L"");
	SetDlgItemText(IDC_EDIT_ALTER_DATE, L"");
	SetDlgItemText(IDC_EDIT_VISIT_DATA, L"");
	//��ǰ���ڵĸ�������teb�ؼ���teb�ؼ��ĸ����ڲ���������
	GetParent()->GetParent()->SendMessage(WM_END_PARSE_PE);
}


BOOL CMainPage::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	//���ó�����
	GetDlgItem(IDC_STATIC_BLOG)->GetWindowRect(&m_Rect);
	ScreenToClient(&m_Rect);

	m_cfNtr = this->GetFont();
	m_cfNtr->GetLogFont(&m_lfNtr);
	m_cfNtr->GetLogFont(&m_lfUL);
	m_lfUL.lfUnderline = TRUE;
	m_cfUL.CreateFontIndirect(&m_lfUL);

	m_brush.CreateSysColorBrush(COLOR_MENU);
	m_color = RGB(0, 0, 0);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}


void CMainPage::OnMouseMove(UINT nFlags, CPoint point)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	if (point.x > m_Rect.left && point.x < m_Rect.right && point.y < m_Rect.bottom && point.y > m_Rect.top)
	{
		HCURSOR hCursor;
		hCursor = ::LoadCursor(NULL, IDC_HAND);
		::SetCursor(hCursor);

		GetDlgItem(IDC_STATIC_BLOG)->SetFont(&m_cfUL);
		m_color = RGB(0, 0, 225);
		CStatic* m_pStatic = (CStatic*)GetDlgItem(IDC_STATIC_BLOG);
		m_pStatic->RedrawWindow();
	}
	else
	{
		GetDlgItem(IDC_STATIC_BLOG)->SetFont(m_cfNtr);

		m_color = RGB(0, 0, 0);
		CStatic* m_pStatic = (CStatic*)GetDlgItem(IDC_STATIC_BLOG);
		m_pStatic->RedrawWindow();
	}

	CDialogEx::OnMouseMove(nFlags, point);
}


void CMainPage::OnLButtonDown(UINT nFlags, CPoint point)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	if (point.x > m_Rect.left && point.x < m_Rect.right && point.y < m_Rect.bottom && point.y > m_Rect.top)
	{
		ShellExecute(NULL, NULL, L"http://blog.csdn.net/sinat_34260423", NULL, NULL, SW_NORMAL);
	}

	CDialogEx::OnLButtonDown(nFlags, point);
}


HBRUSH CMainPage::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  �ڴ˸��� DC ���κ�����

	if (nCtlColor == CTLCOLOR_STATIC)
	{
		pDC->SetBkMode(TRANSPARENT);
		pDC->SetTextColor(m_color);

		return (HBRUSH)m_brush.GetSafeHandle();
	}

	// TODO:  ���Ĭ�ϵĲ������軭�ʣ��򷵻���һ������
	return hbr;
}
