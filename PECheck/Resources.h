#pragma once
#include "afxcmn.h"


// CResources 对话框

class CResources : public CDialogEx
{
	DECLARE_DYNAMIC(CResources)

public:
	CResources(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CResources();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_RESOURCES };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CTreeCtrl m_SectionTree;
	HTREEITEM m_hRoot;     // 树的根节点的句柄   
	HTREEITEM m_hSecondItem; // 可表示任一分类节点的句柄   
	HTREEITEM m_hThirdItem;  // 可表示任一文章节点的句柄   
};
