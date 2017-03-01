#pragma once
#include "afxcmn.h"


// CImport 对话框

class CImport : public CDialogEx
{
	DECLARE_DYNAMIC(CImport)

public:
	CImport(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CImport();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_IMPORT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_ImportList;
	virtual BOOL OnInitDialog();
};
