#pragma once


// CFileHeader 对话框

class CFileHeader : public CDialogEx
{
	DECLARE_DYNAMIC(CFileHeader)

public:
	CFileHeader(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CFileHeader();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_FILE_HEADER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
