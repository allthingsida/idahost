#pragma once

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>

static inline COORD coords_zero = { 0, 0 };

class ConsoleState
{
private:
    CHAR_INFO* buffer = nullptr;
    COORD bufferSize;
    COORD cursorPosition;
    SMALL_RECT consoleWriteArea;
    CONSOLE_SCREEN_BUFFER_INFOEX bufferInfoEx;

public:
    ~ConsoleState()
    {
        free_buffer();
    }

    void free_buffer()
    {
        if (buffer != nullptr)
        {
            free(buffer);
            buffer = nullptr;
        }
    }

    bool save()
    {
        free_buffer();
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Get extended screen buffer information
        this->bufferInfoEx.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);
        if (!GetConsoleScreenBufferInfoEx(hConsole, &(this->bufferInfoEx)))
            return false;

        this->bufferSize = this->bufferInfoEx.dwSize;  // This reflects the total size of the console buffer
        this->cursorPosition = this->bufferInfoEx.dwCursorPosition;
        this->consoleWriteArea = this->bufferInfoEx.srWindow;

        // Allocate buffer to store the entire console screen
        this->buffer = (CHAR_INFO*)malloc(this->bufferSize.X * this->bufferSize.Y * sizeof(CHAR_INFO));
        if (this->buffer == NULL)
            return false;

        // Read the entire console buffer
        SMALL_RECT readRegion = { 0, 0, this->bufferSize.X - 1, this->bufferSize.Y - 1 };

        if (!ReadConsoleOutput(hConsole, this->buffer, this->bufferSize, coords_zero, &readRegion))
        {
            free_buffer();
            return false;
        }
        return true;
    }

    bool restore()
    {
        if (buffer == nullptr)
            return false;

        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Set screen buffer size first to ensure it can hold the restored data
        SetConsoleScreenBufferSize(hConsole, this->bufferSize);

        // Restore the buffer information
        SetConsoleScreenBufferInfoEx(hConsole, &(this->bufferInfoEx));

        // Write the saved buffer back to the console
        SMALL_RECT writeRegion = { 0, 0, this->bufferSize.X - 1, this->bufferSize.Y - 1 };
        if (!WriteConsoleOutput(hConsole, this->buffer, this->bufferSize, coords_zero, &writeRegion))
            return false;

        // Restore cursor position
        SetConsoleCursorPosition(hConsole, this->cursorPosition);
        return true;
    }
};

class Console
{
private:
    static inline HWND s_hwndConsole = NULL;

    static bool IsConsoleApp_(bool* is_console)
    {
        *is_console = false;
        // Get a handle to the executable file of the current process
        HMODULE hModule = GetModuleHandle(NULL);
        if (hModule == NULL)
            return false;

        // Get the DOS header
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        // Get the PE header
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return false;

        // Check the Subsystem field in the Optional Header
        WORD subsystem = pNtHeaders->OptionalHeader.Subsystem;
        *is_console = (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
        return true;
    }


public:
    static void clear_screen()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        DWORD cellCount;
        DWORD written;

        if (GetConsoleScreenBufferInfo(hConsole, &csbi))
        {
            cellCount = csbi.dwSize.X * csbi.dwSize.Y;
            // Fill the entire buffer with spaces
            FillConsoleOutputCharacter(
                hConsole,
                (TCHAR)' ',
                cellCount,
                coords_zero,
                &written);

            // Fill the entire buffer with the current attributes
            FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, coords_zero, &written);

            // Set the buffer size to exactly match the current window size
            COORD newBufferSize;
            newBufferSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            newBufferSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
            SetConsoleScreenBufferSize(hConsole, newBufferSize);

            // Move the cursor to the home position
            SetConsoleCursorPosition(hConsole, coords_zero);
        }
    }

    static void write_xy(DWORD x, DWORD y, LPCTSTR message)
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD pos = { (SHORT)x, (SHORT)y };
        SetConsoleCursorPosition(hConsole, pos);
        DWORD written;
        WriteConsole(hConsole, message, _tcslen(message), &written, NULL);
    }

    static void SetupNewConsole(bool bHidden = true)
    {
        // Set up a new console only if this is a GUI app
        if (IsConsoleApp())
            return;

        // Set up a new console only once
        static bool bOnlyOnce = false;
        if (bOnlyOnce)
            return;

        bOnlyOnce = true;
        // Allocate a console for this app
        AllocConsole();

        // Redirect the standard input/output/error streams to the console
        FILE* fp;
        freopen_s(&fp, "CONIN$", "r", stdin);
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);

        // Make cout, wcout, cin, wcin, wcerr, cerr, wclog and clog point to console as well
        std::ios::sync_with_stdio();

        s_hwndConsole = GetConsoleWindow();
        if (bHidden)
            ShowWindow(s_hwndConsole, SW_HIDE);
    }

    static void Show(bool bShow = true)
    {
        if (s_hwndConsole != NULL)
            ShowWindow(s_hwndConsole, bShow ? SW_SHOW : SW_HIDE);
    }

    static bool IsConsoleApp()
    {
        static bool bIsConsoleAppSet = false;
        static bool bIsConsoleApp = false;
        if (!bIsConsoleAppSet)
        {
            bIsConsoleAppSet = true;
            (void)IsConsoleApp_(&bIsConsoleApp);
        }
        return bIsConsoleApp;
    }
};
