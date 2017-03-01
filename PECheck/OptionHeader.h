#pragma once
#include "afxcmn.h"


// COptionHeader 对话框

class COptionHeader : public CDialogEx
{
	DECLARE_DYNAMIC(COptionHeader)

public:
	COptionHeader(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~COptionHeader();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_OPTION_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
};
