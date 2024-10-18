#include "idahost.h"
#include "pe_mapper.hpp"
#include "win_utils.hpp"

// TODO: test the TVHEADLESS environment variable:
// - TVHEADLESS disable all output (for i/o redirection)
//              if this variable defined, the TVOPT variable is ignored
//              This environment variable also works also in graphical versions of
//              IDA. When set, the graphical interface will not restore desktops,
//              toolbars or show the main window.

struct idahost_cmdline_helper_t: idahost_t::rawoptions_t
{
    // Computed
    std::wstring full_path_;
    int argc_;
    wchar_t** argv_;
    std::vector<wchar_t> cmd_line_;

    wchar_t* get_commandline() {
        return &cmd_line_[0];
    }

    int* get_p_argc(void) {
        return &argc_;
    }

    wchar_t*** get_p_argv(void) {
        return &argv_;
    }

    void reset()
    {
        for (int i = 0; i < argc_; ++i)
            delete[] argv_[i];
        delete[] argv_;
        argc_ = 0;
        argv_ = nullptr;
    }

    bool auto_detect_idadir()
    {
        qstring _idadir;
        if (qgetenv("IDADIR", &_idadir))
        {
            //idadir = _idadir.c_str();
            qwstring _widadir;
            utf8_utf16(&_widadir, _idadir.c_str());
            idadir = _widadir.c_str();
            return true;
        }
        wchar_t path[MAX_PATH * 4];
        SearchPathW(nullptr, L"ida64.dll", nullptr, MAX_PATH * 4, path, nullptr);
        if (path[0] != 0)
        {
            wchar_t* p = wcsrchr(path, L'\\');
            if (p != nullptr)
            {
                *p = 0;
                idadir = path;
                return true;
            }
        }
        return false;
    }

    bool finalize()
    {
        if (idadir.empty())
        {
            auto_detect_idadir();
            if (idadir.empty())
                return false;
        }

        reset();
        argc_ = args.size() + 1;
        argv_ = new wchar_t* [argc_];
        if (argv_ == nullptr)
            return false;

        for (int i = 0; i < argc_; ++i)
            argv_[i] = nullptr;

        full_path_ = idadir + L"\\" + idabin;
        argv_[0] = new wchar_t[full_path_.size() + 1];
        if (argv_[0] == nullptr)
        {
            delete[] argv_;
            return false;
        }

        wcscpy(argv_[0], full_path_.c_str());

        for (size_t i = 0; i < args.size(); ++i)
        {
            argv_[i + 1] = new wchar_t[args[i].size() + 1];
            if (argv_[i + 1] == nullptr)
            {
                reset();
                return false;
            }
            wcscpy(argv_[i + 1], args[i].c_str());
        }

        // Add command line
        std::wstring cmd_line = L'"' + full_path_;
        cmd_line.push_back(L'"');
        for (const auto& arg : args)
            cmd_line += L" " + arg;
        cmd_line_ = std::vector<wchar_t>(cmd_line.begin(), cmd_line.end());
        cmd_line_.push_back(L'\0');  // Null-terminate the command line    
        return true;
    }

    ~idahost_cmdline_helper_t() {
        reset();
    }

    void set_args(
        const wchar_t* provider_path,
        const wchar_t* provider_name,
        const std::vector<std::wstring>& provider_args)
    {
        this->idadir = provider_path;
        if (provider_name != nullptr)
            this->idabin = provider_name;
        this->args = provider_args;
    }

    void clear_args() {
        args.clear();
    }

    void add_arg(const std::wstring &arg) {
        args.push_back(arg);
    }
};

idahost_t idahost;
static idahost_cmdline_helper_t idahost_options;

static wchar_t*** _my__p___wargv(void) {
    return idahost_options.get_p_argv();
}

static int* _my__p___argc(void) {
    return idahost_options.get_p_argc();
}

static wchar_t* _my_GetCommandLineW(void) {
    return idahost_options.get_commandline();
}

static DWORD WINAPI _my_GetModuleFileNameW(
    HMODULE hModule,
    LPWSTR lpFilename,
    DWORD nSize)
{
    if (hModule == nullptr)
    {
        DWORD len = idahost_options.full_path_.size();
        if (nSize < len)
            return len;
        wcscpy(lpFilename, idahost_options.full_path_.c_str());
        return len;
    }

    return GetModuleFileNameW(hModule, lpFilename, nSize);
}

extern "C" __declspec(dllexport) IDAHostInterface * __cdecl get_idahost_interface()
{
    return &idahost;
}

static VOID CALLBACK s_RunProviderFiberProc(LPVOID lpParameter) {
    ((idahost_t*)lpParameter)->internal_run_provider();
}

idahost_t::idahost_t() 
{
    cs_ = new ConsoleState();
    options = &idahost_options;
}

idahost_t::~idahost_t() {
    delete provider_pe_;
    delete cs_;
}

void idahost_t::save_screen()
{
    cs_->save();
}

void idahost_t::restore_screen()
{
    cs_->restore();
}

bool idahost_t::init(const rawoptions_t& opt)
{
    options->set_args(
        opt.idadir.c_str(), 
        opt.idabin.c_str(), 
        opt.args);
    return init_internal();
}

bool idahost_t::init(const options_t& opt)
{
    if (!Console::IsConsoleApp())
        Console::SetupNewConsole(true);

    options->set_args(opt.idadir.c_str(), opt.idabin.c_str(), {});

    if (!opt.log_file.empty())
        options->add_arg(L"-L" + opt.log_file);

    if (opt.dbg)
    {
        wchar_t dbg_str[30];
        swprintf(dbg_str, 30, L"-z%X", opt.dbg);
        options->add_arg(dbg_str);
    }
    options->add_arg(opt.input_file);
    return init_internal();
}

bool idahost_t::init_internal()
{
    options->finalize();
    err_.clear();
    if (IsThreadAFiber())
    {
        host_fiber_ = GetCurrentFiber();
        host_owns_fiber_ = false;
    }
    else
    {
        host_fiber_ = ConvertThreadToFiber(this);
        host_owns_fiber_ = true;
    }

    if (host_fiber_ == NULL)
    {
        err_ = "Failed to convert thread to fiber!";
        return false;
    }

    wchar_t cur_dir[MAX_PATH * 4];
    GetCurrentDirectoryW(MAX_PATH * 4, cur_dir);
    // Create the foreign fiber
    provider_fiber_ = CreateFiber(
        1024 * 1024 * 8,
        s_RunProviderFiberProc,
        this);
    if (provider_fiber_ == NULL)
    {
        err_ = "Failed to create foreign fiber";
        return false;
    }

    // Let the provider run up to the appropriate checkpoint
    SwitchToFiber(provider_fiber_);
    // Restore the working directory
    SetCurrentDirectoryW(cur_dir);
    return true;
}

void idahost_t::term()
{
    save_screen();
    term_database();
    restore_screen();

    DeleteFiber(provider_fiber_);
    if (host_owns_fiber_ && host_fiber_ != nullptr)
        ConvertFiberToThread();

    cs_->free_buffer();
    provider_fiber_ = nullptr;
    host_fiber_ = nullptr;
}

void idahost_t::return_to_host()
{
    restore_screen();
    SwitchToFiber(host_fiber_);
}

void idahost_t::set_msg_handler(void* ud, host_msg_handler_t cb) 
{
    msg_handler_ = cb;
    msg_ud_ = ud;
}

void idahost_t::ui_msg_(const char* format, va_list args)
{
    if (msg_handler_ != nullptr)
        msg_handler_(msg_ud_, format, args);
    else
        vprintf(format, args);
}

void idahost_t::internal_run_provider()
{
    // Set up provider's environment
    //SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_USER_DIRS);
    SetDllDirectoryW(this->options->idadir.c_str());
    SetCurrentDirectoryW(this->options->idadir.c_str());
    qstring env;
    utf16_utf8(&env, this->options->idadir.c_str());
    qsetenv("IDADIR", env.c_str());

    this->provider_pe_ = PEMapper::CreateFromFile(this->options->idabin.c_str());
    if (this->provider_pe_ == nullptr)
        return;

    this->provider_pe_->SetResolveImport(
        [](void* ud, LPCSTR, HMODULE, LPCSTR sym_name, DWORD64* addr) -> bool {
            return ((idahost_t*)ud)->CanResolveImport(sym_name, addr);
        }, this);

    // Save host's screen before handing over to the provider
    this->save_screen();
    bool success = this->provider_pe_->Run();
    // ...never reaches this point (but just in case)
    delete this->provider_pe_;
    this->provider_pe_ = nullptr;
    SwitchToFiber(this->provider_fiber_);
}

void idahost_t::interact()
{
    bool is_console = Console::IsConsoleApp();
    if (!is_console)
        Console::Show(true);

    save_screen();
    refresh_idaview_anyway();
    SwitchToFiber(provider_fiber_);
    restore_screen();
    if (!is_console)
        Console::Show(false);
}

bool idahost_t::CanResolveImport(const char *sym_name, uint64_t* addr)
{
    do
    {
        if (strcmp(sym_name, "__p___argc") == 0)
            *addr = (DWORD64)_my__p___argc;
        else if (strcmp(sym_name, "__p___wargv") == 0)
            *addr = (DWORD64)_my__p___wargv;
        else if (strcmp(sym_name, "GetCommandLineW") == 0)
            *addr = (DWORD64)_my_GetCommandLineW;
        else if (strcmp(sym_name, "GetModuleFileNameW") == 0)
            *addr = (DWORD64)_my_GetModuleFileNameW;
        else
            break;
        return true;
    } while (false);
    return false;
}
