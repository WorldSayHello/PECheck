#pragma once
#include "afxcmn.h"


// CSection �Ի���

class CSection : public CDialogEx
{
	DECLARE_DYNAMIC(CSection)

public:
	CSection(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSection();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_SECTION };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_SectionList;
	virtual BOOL OnInitDialog();
};
