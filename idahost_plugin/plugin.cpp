#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <windows.h>
#include "../idahost/include/idahost_interface.h"

class idahost_plgmod_t : 
    public plugmod_t, public event_listener_t
{
    bool initial_return_to_host_ = false;
    IDAHostInterface* host_;

public:
    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
        switch (code)
        {
            //< ui: Show a message box.
            case ui_mbox:
            {
                auto kind = va_arg(va, mbox_kind_t);
                auto format = va_arg(va, const char*);
                auto args = va_arg(va, va_list);
                if (format == nullptr)
                    format = "";
                //printf("ui_msgbox[%s]: %s\n", mbox_kind_t2s(kind), format);
                printf("ui_msgbox[%d]: %s\n", kind, format);
                //vprintf(format, args);
                return 0;
            }
            case ui_msg:
            {
                auto format = va_arg(va, const char*);
                auto args = va_arg(va, va_list);
                (void)vprintf(format, args);
                return 1;
            }
            case ui_ready_to_run:
            {
                if (initial_return_to_host_)
                    break;

                initial_return_to_host_ = true;
                host_->return_to_host();
                break;
            }
        }
        return 0;
    }

    idahost_plgmod_t(IDAHostInterface* host) : host_(host)
    {
        hook_event_listener(HT_UI, this);
    }

    bool run(size_t) override
    {
        if (ask_yn(ASKBTN_NO, "HIDECANCEL\nDo you want to return to the host?") == ASKBTN_YES)
            host_->return_to_host();

        return true;
    }
    
    static idahost_plgmod_t* create()
    {
        auto get_host_interface = (get_host_interface_proc_t)GetProcAddress(
            GetModuleHandle(nullptr),
            "get_idahost_interface");
        if (get_host_interface == nullptr)
        {
            warning("Failed to get host interface\n");
            return nullptr;
        }

        return new idahost_plgmod_t(get_host_interface());
    }
};

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,       // plugin flags
    []()->plugmod_t* { return idahost_plgmod_t::create(); },
    nullptr,            // terminate. this pointer may be nullptr.
    nullptr,            // invoke plugin
    "",        // long comment about the plugin
    "",        // multiline help about the plugin
    "idahost: Exit interactive mode",        // the preferred short name of the plugin
    ""       // the preferred hotkey to run the plugin
};
