#pragma once

#include <stdarg.h>

struct IDAHostInterface
{
    virtual void return_to_host() = 0;
    virtual void save_screen()  = 0;
    virtual void restore_screen() = 0;
    virtual void interact() = 0;
    virtual void ui_msg_(const char* format, va_list args) = 0;
    virtual ~IDAHostInterface() = 0 { };
    //;!TODO: transaction_begin, transaction_end, transaction_abort
};

typedef IDAHostInterface* (*get_host_interface_proc_t)();
