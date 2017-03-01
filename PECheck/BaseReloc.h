#pragma once
#include "afxcmn.h"


// CBaseReloc 对话框

class CBaseReloc : public CDialogEx
{
	DECLARE_DYNAMIC(CBaseReloc)

public:
	CBaseReloc(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CBaseReloc();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_BASE_RELC };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_BaseRelocList;
	virtual BOOL OnInitDialog();
};
