#pragma once
#include "afxcmn.h"


// CImport �Ի���

class CImport : public CDialogEx
{
	DECLARE_DYNAMIC(CImport)

public:
	CImport(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CImport();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_IMPORT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_ImportList;
	virtual BOOL OnInitDialog();
};
