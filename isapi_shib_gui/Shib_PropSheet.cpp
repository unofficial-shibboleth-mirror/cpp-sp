#include <windows.h>
#include "Shib_PropSheet.h"
#include <crtdbg.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
#include "resource.h"
#include "globals.h"
#include "atou.h"
using namespace std;

	
void Shib_PropSheet::ReplaceSlashes(string& buf)
{
	size_t p=0;

	while ((p = buf.find('/',p)) != string::npos) {
		buf.at(p) = '\\';
		p++;
	}
}

Shib_PropSheet::Shib_PropSheet() : m_cref(0)
{
	for (int i=0;i<NUM_DIRECTIVES;i++) {
		directive[i].Init_Directive(i);
	}

	pwzService=NULL;
	pwzParentPath=NULL;
	pwzNode=NULL;
	pwzMetaPath=NULL;
	pwzMachineName=NULL;
	pwzInstance=NULL;
	pwzRegPath=NULL;
	OBJECT_CREATED
}


Shib_PropSheet::~Shib_PropSheet()
{
	if ( pwzService )
		::LocalFree(pwzService); 
	if ( pwzParentPath )
		::LocalFree(pwzParentPath);
	if ( pwzNode )
		::LocalFree(pwzNode);
	if ( pwzMetaPath )
		::LocalFree(pwzMetaPath);
	if ( pwzMachineName )
		::LocalFree(pwzMachineName);
	if ( pwzInstance )
		::LocalFree(pwzInstance);
	if ( pwzRegPath )
		::LocalFree(pwzRegPath);
	
	OBJECT_DESTROYED
}

///////////////////////
// IUnknown implementation
///////////////////////

STDMETHODIMP Shib_PropSheet::QueryInterface(REFIID riid, LPVOID *ppv)
{
	if (!ppv)
		return E_FAIL;
	
	*ppv = NULL;
	
	if (IsEqualIID(riid, IID_IUnknown))
		*ppv = static_cast<IExtendPropertySheet *>(this);
	else if (IsEqualIID(riid, IID_IExtendPropertySheet))
		*ppv = static_cast<IExtendPropertySheet *>(this);
	
	if (*ppv) 
	{
		reinterpret_cast<IUnknown *>(*ppv)->AddRef();
		return S_OK;
	}
	
	return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) Shib_PropSheet::AddRef()
{
	return InterlockedIncrement((LONG *)&m_cref);
}

STDMETHODIMP_(ULONG) Shib_PropSheet::Release()
{
	if (InterlockedDecrement((LONG *)&m_cref) == 0)
	{
		// we need to decrement our object count in the DLL
		delete this;
		return 0;
	}
	
	return m_cref;
}

HRESULT Shib_PropSheet::ExtractData( IDataObject* piDataObject,
									CLIPFORMAT   cfClipFormat,
									BYTE*        pbData,
									DWORD        cbData )
{
	HRESULT hr = S_OK;
	
	FORMATETC formatetc = {cfClipFormat, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
	STGMEDIUM stgmedium = {TYMED_HGLOBAL, NULL};
	
	stgmedium.hGlobal = ::GlobalAlloc(GPTR, cbData);
	do 
	{
		if (NULL == stgmedium.hGlobal)
		{
			hr = E_OUTOFMEMORY;
			break;
		}
		hr = piDataObject->GetDataHere( &formatetc, &stgmedium );
		if ( FAILED(hr) )
		{
			break;
		}
		
		BYTE* pbNewData = reinterpret_cast<BYTE*>(stgmedium.hGlobal);
		if (NULL == pbNewData)
		{
			hr = E_UNEXPECTED;
			break;
		}
		::memcpy( pbData, pbNewData, cbData );
	} while (FALSE); 
	
	if (NULL != stgmedium.hGlobal)
	{
		::GlobalFree(stgmedium.hGlobal);
	}
	return hr;
} 


void Shib_PropSheet::PopulateComboBox()
{
	
	for (int i = 0; i <  NUM_DIRECTIVES; i++)
	{	
		LRESULT index = SendMessage(hProps, CB_ADDSTRING, 0, (LPARAM) (LPWSTR) directive[i].name.c_str());
		LRESULT debug = SendMessage(hProps, CB_SETITEMDATA, (WPARAM)index, (LPARAM)i );
	}
	
	LRESULT debug = SendMessage(hProps, CB_SETCURSEL, 0, 0);	// wparam = index, lparam = not used
	
}

BOOL Shib_PropSheet::UpdateNewValue() {
	_TCHAR value[MAX_REG_BUFF];
	
	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	UINT i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );
	
	if (directive[i].type == D_BOUND_INT || directive[i].type == D_BOUND_STRING) {
		index = SendMessage(hValueBox, CB_GETCURSEL, 0,0); 
		if (index == CB_ERR) { return FALSE; }
		LRESULT debug = SendMessage(hValueBox, CB_GETLBTEXT, (WPARAM)index, (LPARAM)value );
	} else {
		LRESULT debug = SendMessage(hValueEdit, WM_GETTEXT, (WPARAM)MAX_REG_BUFF, (LPARAM)value );
	}
	
	directive[i].new_value = value;
	if (!_tcsicmp(directive[i].value.c_str(),value)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

void Shib_PropSheet::GetHandles() {
	hValueBox       = GetDlgItem(hwndDlg, IDC_ValueBox);
	hValueEdit      = GetDlgItem(hwndDlg, IDC_ValueEdit);
	hInheritedFrom  = GetDlgItem(hwndDlg, IDC_InheritedFrom);
	hMoreInfo       = GetDlgItem(hwndDlg, IDC_MoreInfo);
	hProps	        = GetDlgItem(hwndDlg, IDC_PROPS);
	hDelete         = GetDlgItem(hwndDlg, IDC_Delete);
}

void Shib_PropSheet::PopulatePage() {
	
	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	LRESULT i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );
	
	Set_Delete_Button(i);

	if (directive[i].type == D_BOUND_INT || directive[i].type == D_BOUND_STRING) {
		ShowWindow(hValueEdit,SW_HIDE);
		ShowWindow(hValueBox,SW_SHOW);
		SendMessage(hValueBox,CB_RESETCONTENT,0,0);
		for(int vi=0;vi < NUM_BOUND_VAL;vi++) {
			if (directive[i].bound_val[vi].length()) {
				LRESULT index = SendMessage(hValueBox, CB_INSERTSTRING, -1, (LPARAM) (LPWSTR) directive[i].bound_val[vi].c_str());
			}
		}
		
		SendMessage(hValueBox, WM_SETTEXT, 0, (LPARAM) directive[i].new_value.c_str());
	} else {
		ShowWindow(hValueEdit,SW_SHOW);
		ShowWindow(hValueBox,SW_HIDE);
		SendMessage(hValueEdit, WM_SETTEXT, 0, (LPARAM) directive[i].new_value.c_str());
	}
	
	SendMessage(hMoreInfo, WM_SETTEXT, 0, (LPARAM) directive[i].description.c_str());
	SendMessage(hInheritedFrom, WM_SETTEXT, 0, (LPARAM) directive[i].defined_in.c_str());
	
}

void Shib_PropSheet::DeleteValue() {

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	LRESULT i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );

	directive[i].DeleteValue();

}

void Shib_PropSheet::SetupPropSheet() {

	GetHandles();
	ReadCurrentValues();
	PopulateComboBox();	
	PopulatePage();

}

BOOL CALLBACK Shib_PropSheet::DialogProc(
										 HWND hwndDlg,  // handle to dialog box
										 UINT uMsg,     // message
										 WPARAM wParam, // first message parameter
										 LPARAM lParam  // second message parameter
										 )
{
	
	if (uMsg == WM_INITDIALOG) {
		Shib_PropSheet *pThis=reinterpret_cast<Shib_PropSheet *>(reinterpret_cast<PROPSHEETPAGE *>(lParam)->lParam);
		pThis->hwndDlg=hwndDlg;                              //store property page handle in class
		SetWindowLongPtr(hwndDlg,DWLP_USER,(LONG_PTR)pThis); //store class pointer in property page
		pThis->SetupPropSheet();
	} else { 
		Shib_PropSheet *pThis = reinterpret_cast<Shib_PropSheet *>(reinterpret_cast<PROPSHEETPAGE *>(GetWindowLongPtr(hwndDlg,DWLP_USER)));  //retrieve class pointer from property page
		switch (uMsg) {
		case WM_COMMAND:
			if (HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == CBN_SELCHANGE) {
				if ((HWND)lParam == GetDlgItem(hwndDlg,IDC_PROPS)) {  //if the user changes directives
					pThis->PopulatePage();  //redraw page
				} else {
					if (pThis->UpdateNewValue()) {
						//if anything else changes, light the apply button
						SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0); 
					}
				}
			}
			if (wParam == IDC_Delete) { 
				pThis->DeleteValue();
				pThis->PopulatePage();
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, (WPARAM)hwndDlg, 0); //light apply
			} else if (wParam == IDC_Refresh) {
				pThis->ReadCurrentValues(); //refresh values
				pThis->PopulatePage();      //refresh page
			}
			break;
			
		case WM_DESTROY:
			break;
			
		case WM_NOTIFY:
			switch (((NMHDR *) lParam)->code) {
			case PSN_APPLY:
				pThis->UpdateNewValue();    //collect last-minute changes
				pThis->WriteValues();       //write new values
				pThis->ReadCurrentValues(); //refresh values
				pThis->PopulatePage();      //refresh page
				return PSNRET_NOERROR;
			}
			break;
		}
	}
	return FALSE;  //Seems to not fall through to parent page if you use DefWindowProc
	//return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

///////////////////////////////
// Interface IExtendPropertySheet
///////////////////////////////
HRESULT Shib_PropSheet::CreatePropertyPages( 
											/* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
											/* [in] */ LONG_PTR handle,
											/* [in] */ LPDATAOBJECT lpIDataObject)
{
	PROPSHEETPAGE psp;
	HPROPSHEETPAGE hPage = NULL;
	
	// cache this handle so we can call MMCPropertyChangeNotify
	m_ppHandle = handle;
	
	UINT s_cfInstance =
		RegisterClipboardFormat(_T("ISM_SNAPIN_INSTANCE"));
	UINT s_cfMachineName =
		RegisterClipboardFormat(_T("ISM_SNAPIN_MACHINE_NAME"));
	UINT s_cfMetaPath =
		RegisterClipboardFormat(_T("ISM_SNAPIN_META_PATH"));
	UINT s_cfNode =
		RegisterClipboardFormat(_T("ISM_SNAPIN_NODE"));
	UINT s_cfParentPath =
		RegisterClipboardFormat(_T("ISM_SNAPIN_PARENT_PATH"));
	UINT s_cfService =
		RegisterClipboardFormat(_T("ISM_SNAPIN_SERVICE"));
	
	if ( !lpProvider || !lpIDataObject )
		return E_POINTER;
	
	HRESULT hr = S_OK;
	
	DWORD dwLength = MAX_PATH * sizeof(_TCHAR);
	DWORD dwWLength = MAX_PATH * sizeof(wchar_t);
	
	LPWSTR pwztInstance = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));
	LPWSTR pwztMachineName = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));
	LPWSTR pwztMetaPath = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));
	LPWSTR pwztNode = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));
	LPWSTR pwztParentPath = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));
	LPWSTR pwztService = reinterpret_cast<LPWSTR>(::LocalAlloc(LPTR, dwWLength));

	if ( pwztInstance )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfInstance, pwztInstance, dwLength);
	if ( pwztMachineName )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfMachineName, pwztMachineName, dwLength);
	if ( pwztMetaPath )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfMetaPath, pwztMetaPath, dwLength);
	if ( pwztNode )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfNode, pwztNode, dwLength);
	if ( pwztParentPath )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfParentPath, pwztParentPath, dwLength);
	if ( pwztService )
		Shib_PropSheet::ExtractWString(lpIDataObject, s_cfService, pwztService, dwLength);

	/* IIS only supports Unicode clipboard formats */
#ifdef _UNICODE
	pwzInstance = pwztInstance;
	pwzMachineName = pwztMachineName;
	pwzMetaPath = pwztMetaPath;
	pwzNode = pwztNode;
	pwzParentPath = pwztParentPath;
	pwzService = pwztService;
#else
	pwzInstance = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));
	pwzMachineName = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));
	pwzMetaPath = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));
	pwzNode = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));
	pwzParentPath = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));
	pwzService = reinterpret_cast<LPSTR>(::LocalAlloc(LPTR, dwLength));

	UnicodeToAnsi(pwztInstance,&pwzInstance);
	UnicodeToAnsi(pwztMachineName,&pwzMachineName);
	UnicodeToAnsi(pwztMetaPath,&pwzMetaPath);
	UnicodeToAnsi(pwztNode,&pwzNode);
	UnicodeToAnsi(pwztParentPath,&pwzParentPath);
	UnicodeToAnsi(pwztService,&pwzService);

	if ( pwztService )
		::LocalFree(pwztService); 
	if ( pwztParentPath )
		::LocalFree(pwztParentPath);
	if ( pwztNode )
		::LocalFree(pwztNode);
	if ( pwztMetaPath )
		::LocalFree(pwztMetaPath);
	if ( pwztMachineName )
		::LocalFree(pwztMachineName);
	if ( pwztInstance )
		::LocalFree(pwztInstance);

#endif

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		directive[i].MachineName = pwzMachineName; 
	}
	pwzRegPath = reinterpret_cast<LPTSTR>(::LocalAlloc(LPTR, (dwLength*2)+1));
	
	LPTSTR ppath = _tcschr(pwzParentPath,_T('/'));
	if (ppath) {
		StringCbCopy(pwzRegPath, MAX_PATH*2 ,ppath+1);
		StringCbCat (pwzRegPath, MAX_PATH*2 ,_T("/"));
	} else {
		pwzRegPath[0] = 0;
	}
	StringCbCat(pwzRegPath, MAX_PATH*2 ,pwzNode);
	
	psp.dwSize = sizeof(PROPSHEETPAGE);
	psp.dwFlags = PSP_DEFAULT | PSP_USETITLE | PSP_USEICONID;
	psp.hInstance = g_hinst;
	psp.pszTemplate = MAKEINTRESOURCE(IDD_PROPPAGE);
	psp.pfnDlgProc = DialogProc;
	psp.lParam = reinterpret_cast<LPARAM>(this);
	psp.pszTitle = MAKEINTRESOURCE(IDS_PST_TAB_NAME);
	
	hPage = CreatePropertySheetPage(&psp);
	_ASSERT(hPage);
	
	hr = lpProvider->AddPage(hPage);
	
	return hr;
}

HRESULT Shib_PropSheet::QueryPagesFor( 
									  /* [in] */ LPDATAOBJECT lpDataObject)
{
	return S_OK;
}

void Shib_PropSheet::Set_Delete_Button(int i) {

	if (!_tcsicmp((directive[i].defined_in.c_str() + 1),pwzRegPath)) {
		EnableWindow(hDelete,TRUE);
	} else {
		EnableWindow(hDelete,FALSE);
	}
}

void Shib_PropSheet::ReadSelectedValue() {

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	unsigned int i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );
	directive[i].Set_Path(pwzRegPath);
	directive[i].new_value = directive[i].value;

}

void Shib_PropSheet::ReadCurrentValues() {

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		directive[i].Set_Path(pwzRegPath);
		directive[i].new_value = directive[i].value;
	}
}


void Shib_PropSheet::WriteValues() {
	string RegPath;

	RegPath = _T(SHIB_DEFAULT_WEB_KEY);

	if  (_tcslen(pwzRegPath)) {
		RegPath += _T("\\");
		RegPath += pwzRegPath;
		ReplaceSlashes(RegPath);
	} 
	
	for (int i=0;i<NUM_DIRECTIVES;i++) {
		if (_tcscmp(STR_PENDING_DELETION,directive[i].new_value.c_str())){
			if (_tcsicmp(directive[i].value.c_str(),directive[i].new_value.c_str())) {
				directive[i].WriteValue(RegPath);
			}
		} else { // Commit Delete
			directive[i].DeleteRegVal(RegPath);
		}
	}
}

