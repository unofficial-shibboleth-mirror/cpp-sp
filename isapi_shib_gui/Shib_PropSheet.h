
#ifndef _Shib_PropSheet
#define _Shib_PropSheet

#include <tchar.h>
#include <mmc.h>
#include <string>
using namespace std;

#define D_FREE_STRING 0
#define D_FREE_INT 1
#define D_BOUND_INT 2
#define D_BOUND_STRING 3

typedef _TCHAR pool;

#define STR_THIS_WEB_INSTANCE L"(This web instance)"
#define STR_SERVER_DEFAULT    L"(Server Default)"
#define STR_PROGRAM_DEFAULT   L"(Program Default)"

#include "directives.h"
#include "directive_class.h"

#define debug_break() MessageBox(NULL,L"Break",L"Break",MB_OK);

class Shib_PropSheet : public IExtendPropertySheet
{
        
public:
    Shib_PropSheet();
    ~Shib_PropSheet();

	HWND hwndDlg;
	LPTSTR pwzRegPath;
	LPTSTR pwzMachineName;
	Directive directive[NUM_DIRECTIVES];

	void SetupPropSheet();
	void PopulatePage();
	BOOL UpdateNewValue();
	void DeleteValue();
	void GetHandles();

	///////////////////////////////
    // Interface IUnknown
    ///////////////////////////////
    STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    
    ///////////////////////////////
    // Interface IExtendPropertySheet
    ///////////////////////////////
    virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE CreatePropertyPages( 
        /* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
        /* [in] */ LONG_PTR handle,
        /* [in] */ LPDATAOBJECT lpIDataObject);
        
    virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE QueryPagesFor( 
        /* [in] */ LPDATAOBJECT lpDataObject);

    
private:
    LONG_PTR m_ppHandle;
	LPTSTR pwzInstance;
	LPTSTR pwzMetaPath;
	LPTSTR pwzNode;
	LPTSTR pwzParentPath;
	LPTSTR pwzService;
    pool   p[MAX_REG_BUFF];
	string defined_in;
	HWND hValueBox;      
	HWND hValueEdit;
	HWND hInheritedFrom;
	HWND hMoreInfo;
	HWND hProps;	
	HWND hDelete;
    ULONG				m_cref;
    
	static BOOL CALLBACK DialogProc(HWND hwndDlg,  
        UINT uMsg,     
        WPARAM wParam, 
        LPARAM lParam  
        );
   
    void PopulateComboBox();
	void WriteValues();
	void GetEffectiveValue(int i);
	void ReplaceSlashes(string& buf);
	void ReadCurrentValues();
	void DeleteRegVal(const _TCHAR* szKey, const _TCHAR* szValueName);
	void Set_Delete_Button(int i);
	void ReadSelectedValue();
	void ReadValAsString(LPTSTR key, int i, LPCTSTR defined_in);

    ///////////////////////////////
    // Private IDataObject support bits
    ///////////////////////////////
    HRESULT ExtractData( IDataObject* piDataObject,
        CLIPFORMAT   cfClipFormat,
        BYTE*        pbData,
        DWORD        cbData );
    
    HRESULT ExtractWString( IDataObject *piDataObject,
        CLIPFORMAT   cfClipFormat,
        WCHAR       *pstr,
        DWORD        cchMaxLength)
    {
        return ExtractData( piDataObject, cfClipFormat, (PBYTE)pstr, cchMaxLength );
    }
    
};


#endif _Shib_PropSheet_H_
