#pragma once
#include "afxwin.h"
#include "EditProvider.h"

// CMainPage �Ի���

class CMainPage : public CDialogEx
{
	DECLARE_DYNAMIC(CMainPage)

public:
	CMainPage(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CMainPage();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_MAINPAGE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CEditProvider m_epFilePath;
	CString m_FilePath;
	CRect   m_Rect;
	CFont*  m_cfNtr;
	CFont   m_cfUL;
	COLORREF m_color;
	CBrush  m_brush;
	LOGFONT m_lfNtr, m_lfUL;
	afx_msg void OnBnClickedButtonOpenFile();
	afx_msg void OnBnClickedButtonCloseFile();
	virtual BOOL OnInitDialog();
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
};
