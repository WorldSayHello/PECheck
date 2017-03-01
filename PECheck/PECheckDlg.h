
// PECheckDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "Common.h"
#include "MainPage.h"
#include "DosHeader.h"
#include "FileHeader.h"
#include "OptionHeader.h"
#include "Section.h"
#include "Resources.h"
#include "Import.h"
#include "Export.h"
#include "BaseReloc.h"

// CPECheckDlg 对话框
class CPECheckDlg : public CDialogEx
{
// 构造
public:
	CPECheckDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PECHECK_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CTabCtrl    m_tMenu;
	CRect       m_rect;
	CMainPage   m_MainPage;
	CDosHeader  m_DosHeader;
	CFileHeader m_FileHeader;
	COptionHeader m_OptionHeader;
	CSection    m_Section;
	CResources  m_Resources;
	CExport     m_Export;
	CImport     m_Import;
	CBaseReloc  m_BaseReloc;
	PWSTR       m_wszFilePath;
	PPARSED_PE  m_pParsedPE;

	afx_msg void OnTcnSelchangeTabMenu(NMHDR *pNMHDR, LRESULT *pResult);
protected:
	afx_msg LRESULT OnStartParsePe(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnEndParsePe(WPARAM wParam, LPARAM lParam);
	void SetDosEdit();
	void SetFileEdit();
	void SetOptionEdit32();
	void SetOptionEdit64();
	void SetSectionList();
	void SetResourcesList();
	void SetExportList();
	void SetImportList();
	void SetBaseRelocList();
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);
};
