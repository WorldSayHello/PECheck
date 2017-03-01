#pragma once


// CDosHeader 对话框

class CDosHeader : public CDialogEx
{
	DECLARE_DYNAMIC(CDosHeader)

public:
	CDosHeader(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CDosHeader();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_DOS_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
