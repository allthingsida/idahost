#include <iostream>
#include <pro.h>
#include <kernwin.hpp>
#include <funcs.hpp>
#include "idahost.h"

int main(int argc, char* argv[])
{
    idahost_t::options_t opt = {
        //.idadir = LR"(C:\Users\elias\Tools\idahost8)",
        .input_file = L"C:\\Temp\\test.i64",
        //.log_file = L"myida.log",
        //.dbg = IDA_DEBUG_PLUGIN
    };
    if (!idahost.init(opt))
    {
        std::cout << "Failed to initialize the host:" << idahost.err_str() << std::endl;
        return 1;
    }

    //
    // IDASDK API calls here.
    //
    msg("Hello, World!\n");

    qstring s;
    for (size_t i=0, c = get_func_qty(); i<c; ++i)
    {
        func_t* f = getn_func(i);
        if (get_func_name(&s, f->start_ea) == 0)
            s = "";
        std::cout << std::hex << f->start_ea << ": function: " << s << std::endl;
    }

    idahost.term();

    return 0;
}
