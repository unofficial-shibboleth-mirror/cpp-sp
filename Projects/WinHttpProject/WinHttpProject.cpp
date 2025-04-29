// WinHttpProject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>


#include <Windows.h>
#include <winhttp.h>

using namespace std;

//static WINHTTP_STATUS_CALLBACK Callback;

static void Callback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength)
{
    PCCERT_CONTEXT pCert = NULL;
    DWORD dwSize = sizeof(pCert);
    cout << "Handle " << hex << hInternet <<endl;
    cout << "Context " << dec << dwContext << endl;
    switch (dwInternetStatus) {
        case WINHTTP_CALLBACK_STATUS_SENDING_REQUEST:
            wcout << L"Sending Request (" << dwInternetStatus << L") " << endl;
            if (!WinHttpQueryOption(hInternet, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCert, &dwSize)) {
                cout << "Gack " << GetLastError() << endl;
            } else {
                CHAR buffer[1024];
                CertNameToStrA(X509_ASN_ENCODING, &pCert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, buffer, sizeof(buffer));
                cout << "Subject name " << buffer << endl;
                CertFreeCertificateContext(pCert);
            }
        break;
    
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
        cout << "Read Complete " << dwStatusInformationLength <<endl;
        cout << "Data  " << (PCHAR*) lpvStatusInformation;
        break;
    default:
        cout << "Unknow status " << dwInternetStatus << endl;
        break;
    }
}

static
wstring
Utf8ToUtf16(string InputString) {
    DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, InputString.c_str(), -1, nullptr, 0);

    LPWSTR output = new WCHAR[sizeNeeded +1];

    ZeroMemory(output, sizeNeeded+1);

    if (MultiByteToWideChar(CP_UTF8, 0, InputString.c_str(), -1, output, sizeNeeded) == 0) {
        cerr << "MultiByteToWideChar failure: " <<  GetLastError() << endl;
        throw runtime_error("WinHHHTP failed to initialize");
    }

    wstring result(output);
    delete[] output;

    return result;
}

int main()
{
    string url("https://shibboleth.net/downloads/PGP_KEYS");

    wstring wUrl(Utf8ToUtf16(url));
    URL_COMPONENTS components = { 0 };
    components.dwStructSize= sizeof(components);
    components.dwHostNameLength = -1;
    components.dwUrlPathLength = -1;
    if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &components)) {
        cerr << "WinHttpCrackUrl failure: " << GetLastError() << endl;
        throw runtime_error("WinHHHTP failed to initialize");
    }
    wstring host(components.lpszHostName, components.dwHostNameLength);
    wstring baseUrl(components.lpszUrlPath, components.dwUrlPathLength);

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        // arrange to be called back so e 
        if (WINHTTP_INVALID_STATUS_CALLBACK == WinHttpSetStatusCallback(hSession, Callback, WINHTTP_CALLBACK_STATUS_SENDING_REQUEST, NULL)) {
            cerr << "Urk " << GetLastError() << endl;
            return 1;
        }

        // Specify an HTTP server.
        hConnect = WinHttpConnect(hSession, host.c_str(),
            INTERNET_DEFAULT_HTTPS_PORT, 0);

    }

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", baseUrl.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else
                    printf("%s", pszOutBuffer);

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
    }


    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
