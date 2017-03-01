#pragma once
#include "afxcmn.h"


// CExport 对话框

class CExport : public CDialogEx
{
	DECLARE_DYNAMIC(CExport)

public:
	CExport(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CExport();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_EXPORT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_ExportList;
	virtual BOOL OnInitDialog();
};
