#pragma once

#include <vector>
#include <string>
#include <stdio.h>
#include "idahost_interface.h"
#include <pro.h>
#include <kernwin.hpp>

struct idahost_cmdline_helper_t;
class PEMapper;
struct ConsoleState;

struct idahost_t : public IDAHostInterface
{
public:
    typedef int (*host_msg_handler_t)(void* ud, const char* format, va_list args);

private:
    void* host_fiber_ = nullptr;
    void* provider_fiber_ = nullptr;
    PEMapper* provider_pe_ = nullptr;
    std::string err_;
    bool host_owns_fiber_;
    ConsoleState *cs_ = nullptr;
    idahost_cmdline_helper_t* options;
    host_msg_handler_t msg_handler_ = nullptr;
    void* msg_ud_ = nullptr;

    bool init_internal();
    bool CanResolveImport(const char* sym_name, uint64_t* addr);
public:
    struct rawoptions_t {
        std::wstring idadir;
        std::wstring idabin = L"idat64.exe";
        std::vector<std::wstring> args;
    };
    struct options_t {
        std::wstring idadir;
        std::wstring idabin = L"idat64.exe";
        std::wstring input_file;
        std::wstring log_file;
        int dbg = 0;
    };
    idahost_t();
    ~idahost_t() override;
    void internal_run_provider();

    void set_msg_handler(void* ud, host_msg_handler_t cb);

    const char* err_str() const {
        return err_.c_str();
    }
    void ui_msg_(const char* format, va_list args) override;
    void return_to_host() override;
    void save_screen() override;
    void restore_screen() override;
    void interact();

    void term();
    bool init(const options_t &opt);
    bool init(const rawoptions_t& opt);
};

extern idahost_t idahost;

inline std::ostream& operator<<(std::ostream& os, const qstring& str) {
    os << str.c_str();
    return os;
}
