#pragma once
#include "afxcmn.h"


// CBaseReloc �Ի���

class CBaseReloc : public CDialogEx
{
	DECLARE_DYNAMIC(CBaseReloc)

public:
	CBaseReloc(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CBaseReloc();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_BASE_RELC };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_BaseRelocList;
	virtual BOOL OnInitDialog();
};
