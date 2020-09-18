#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <random>
#include <time.h>
#include <map>
#include <vector>

#define BUFSIZE 512
#define MAXTHREADS 24

std::vector<std::wstring> trap_paths;
std::map<std::wstring, bool> whiteList;
std::wstring trap_target(L"\\\\.\\pipe\\trap");

// Debug Function
std::string GetLastErrorAsString() {

    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
        return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    LocalFree(messageBuffer);

    return message;
}


// Message Box Thread
DWORD WINAPI NotifyUser(LPVOID param) {

    // Get pipe handler
    HANDLE hPipe = (HANDLE)param;

    // Get client PID
    PULONG ppid;
    ppid = new ULONG;
    *ppid = 0;

    BOOL error = GetNamedPipeClientProcessId(hPipe, ppid);
    GetLastErrorAsString();
    printf(GetLastErrorAsString().c_str());

    // Get client name
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, *ppid);
    LPWSTR buffer = new TCHAR[1024];
    PDWORD size = new DWORD;
    *size = 1024;
    QueryFullProcessImageName(hProcess, 0, buffer, size);

    std::wstring program_name(buffer);

    if (!whiteList[program_name]) {
        // Create message box text
        std::wstring message(L"Process connected to pipe with PID ");
        message += std::to_wstring(*ppid);
        message += L" and name ";
        message += program_name;
        message += L". Do you want to stop it?";

        // Launch message box and wait until user responds
        int msgboxID = MessageBox(
            NULL,
            std::wstring(message).c_str(),
            std::wstring(L"R-Locker").c_str(),
            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);


        switch (msgboxID)
        {
        case IDYES:
            // Kill process and close pipe handler
            HANDLE handy;
            handy = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, *ppid);
            TerminateProcess(handy, 0);

            std::wcout << "Terminated process" << "\n";

            break;

        case IDNO:
            // Add process to the white list
            whiteList[program_name] = true;
            break;
        }
    }
    else {
        std::wcout << "Program in the white list " << program_name <<  " tried to access the trap" << "\n";
    }

    // Close handler
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}


// Controller Thread
DWORD WINAPI InstanceThread(LPVOID param) {

    // Initialize variables
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;
    bool fConnected = false;
    DWORD dwThreadId = GetCurrentThreadId();

    // Create named pipe handler
    hPipe = CreateNamedPipe(
        trap_target.c_str(),       // pipe name
        PIPE_ACCESS_OUTBOUND,         // read/write access
        PIPE_TYPE_MESSAGE |         // message type pipe
        PIPE_READMODE_MESSAGE |     // message-read mode
        PIPE_WAIT,                  // blocking mode
        PIPE_UNLIMITED_INSTANCES,   // max. instances
        BUFSIZE,                    // output buffer size
        BUFSIZE,                    // input buffer size
        0,                          // client time-out
        NULL);                      // default security attribute

    // Error check
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        std::wcout << "CreateNamedPipe failed, GLE=" << GetLastError() << "\n";
        return -1;
    }

    std::wcout << "\nThread " << dwThreadId << ": awaiting client connection on " << trap_target.c_str() << "\n";

    // Wait for the client to connect
    fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    // Error check
    if (hPipe == NULL)
    {
        std::wcout << "\nERROR - Pipe Server Failure:\n";
        std::wcout << "InstanceThread got an unexpected NULL value in lpvParam.\n";
        std::wcout << "InstanceThread exitting.\n";
        return (DWORD)-1;
    }

    // Create message box thread
    CreateThread(
        NULL,           // no security attribute
        0,              // default stack size
        NotifyUser,     // thread proc
        (LPVOID)hPipe,  // thread parameter
        0,              // not suspended
        &dwThreadId);   // returns thread ID

    std::wcout << "Thread exiting.\n";

    return 1;
}


// Recursive populate traps
void WalkDirs(std::wstring dir_name) {

    WIN32_FIND_DATA data;
    std::wstring trap_name(dir_name + L"\\a.a");

    // Create trap
    CreateSymbolicLink(trap_name.c_str(), trap_target.c_str(), 0x0);
    SetFileAttributes(trap_name.c_str(), FILE_ATTRIBUTE_HIDDEN);
    trap_paths.push_back(trap_name);

    // Walk dirs
    std::wstring full_dir(dir_name + L"\\*");
    HANDLE hFind = FindFirstFileW(full_dir.c_str(), &data);
    do {
        std::wstring next_dir(data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (next_dir.compare(L".") != 0 && next_dir.compare(L"..") != 0) {
                WalkDirs(dir_name + L"\\" + next_dir);
            }
        }
    } while (FindNextFileW(hFind, &data));
    
    FindClose(hFind);

}

std::wstring GetMainDrive() {
    LPWSTR buffer = new TCHAR[1024];
    int error;
    error = GetEnvironmentVariable(L"SystemDrive", buffer, 1024);
    std::wstring mainDrive(buffer);

    return mainDrive;
}

std::vector<std::wstring> ListSecondaryDrives() {
    std::vector<std::wstring> drivesList;
    
    // Get main drive
    std::wstring mainDrive(GetMainDrive());
    
    // Get the rest of the drives
    DWORD drives = GetLogicalDrives();
    std::wstring drive = L"A:";
    DWORD it = 0x1;

    for (int i = 0; i < sizeof(DWORD); i++) {
        if ((drives & (0x1 << i)) && drive.compare(mainDrive) != 0) {
            drivesList.push_back(drive);
        }
        drive[0]++;
    }

    return drivesList;
}


// Spread traps function
int PopulateTraps() {

    std::wcout << "Generating traps..." << "\n";

    // Get user path
    LPWSTR buffer = new TCHAR[1024];
    int error;
    error = GetEnvironmentVariable(L"userprofile", buffer, 1024);
    if (error == 0) {
        std::wcout << "Error accessing userprofile " << error << "\n";
        return 0;
    }
    
    std::wstring user_path(buffer);

    // Get secondary drives and add the primary one
    std::vector<std::wstring> drives(ListSecondaryDrives());
    drives.push_back(user_path);

    // Walk directories creating traps
    for (auto it = drives.begin(); it != drives.end(); ++it) {
        WalkDirs(*it);
    }

    return 1;
}


// Enum directories with benign .exe files and populate white list
bool EnumDirs(std::vector<std::wstring> roots) {
    WIN32_FIND_DATA rootData;
    WIN32_FIND_DATA programData;
    std::wstring root;

    for (auto it = roots.begin(); it != roots.end(); ++it) {
        root = *it;

        HANDLE hFind = FindFirstFileW((root + L"\\*").c_str(), &rootData);
        do {
            std::wstring next_dir(rootData.cFileName);
            if (rootData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (next_dir.compare(L".") != 0 && next_dir.compare(L"..") != 0) {

                    std::wstring programDir(root + L"\\" + next_dir);
                    HANDLE pFind = FindFirstFileW((programDir + L"\\*").c_str(), &programData);

                    do {
                        std::wstring exeFile(programData.cFileName);
                        std::wstring exePath(programDir + L"\\" + exeFile);
                        LPDWORD lpBinaryType = new DWORD;
                        
                        if (GetBinaryType(exePath.c_str(), lpBinaryType)) {
                            whiteList[exePath] = true;
                        }

                    } while (FindNextFileW(pFind, &programData));

                }
            }
        } while (FindNextFileW(hFind, &rootData));

        FindClose(hFind);
    }

    return true;
}

// Clean traps
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    for (auto it = trap_paths.begin(); it != trap_paths.end(); ++it) {
        DeleteFile((*it).c_str());
    }

    return TRUE;
}


// Main FUnction
int wmain() {

    // Set exit handler
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Set ransom seed
    srand(time(NULL));

    // Initialize variables
    BOOL fConnected = FALSE;
    DWORD dwThreadId = 0, ended_threads = 0;
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
    HANDLE  hThreadArray[MAXTHREADS];

    // Spread traps
    PopulateTraps();

    // Populate white list
    std::vector<std::wstring> roots;
    std::wstring mainDrive(GetMainDrive());
    roots.push_back(mainDrive + L"\\Program Files");
    roots.push_back(mainDrive + L"\\Program Files (x86)");
    EnumDirs(roots);

    // Get number of cores
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    DWORD cores = sys_info.dwNumberOfProcessors;

    std::wcout << "NUMBER OF CORES: " << cores << "\n";

    // Main loop
    for (;;) {
        ended_threads = 0;

        //Launch controller threads
        for (int i = 0; i < cores; i++) {
            std::wcout << "Launching Thread " << i << "\n";
            hThreadArray[i] = CreateThread(
                NULL,           // no security attribute
                0,              // default stack 
                InstanceThread, // thread proc
                (LPVOID)hPipe,  // thread parameter
                0,              // not suspended
                &dwThreadId);   // returns thread ID

            if (hThreadArray[i] == NULL) {
                std::wcout << "CreateThread failed, GLE=" << GetLastError();
                return -1;
            }

        }

        // Wait for (cores - 1) threads to finish
        // Launch new threads when (cores -1) threads have detected a new suspicious process
        while (ended_threads < (cores - 1)) {
            WaitForMultipleObjects(cores, hThreadArray, FALSE, INFINITE);
            ended_threads++;
        }
    }

    return 0;
}
