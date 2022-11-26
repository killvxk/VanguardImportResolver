#include <iostream>
#include <UdLib/UdLib.hpp>
#include <Unicorn/unicorn/unicorn.h>

int main( )
{
    /* initialize unicorn engine */
    std::unique_ptr< uc_engine, decltype( &uc_close ) > Unicorn( ( []( ) {
        uc_engine* Engine;
        uc_open( UC_ARCH_X86, UC_MODE_64, &Engine );

        return Engine;
    } )( ), uc_close );

    /* load vanguard */
    const auto Vanguard = reinterpret_cast< std::uint8_t* >( LoadLibraryExA( "vgk.sys", nullptr, DONT_RESOLVE_DLL_REFERENCES ) );
    std::unique_ptr< std::remove_pointer_t< HANDLE >, decltype( &CloseHandle ) > ScopedVanguard( Vanguard, CloseHandle );

    /* reflect vanguard into unicorn's memory */
    uc_mem_map_ptr( Unicorn.get( ), 0x0, ud::module_t( Vanguard ).size, UC_PROT_ALL, Vanguard );

    /* initialize the stack */
    uc_mem_map( Unicorn.get( ), 0xFFFFFA0000000000, 0x2000, UC_PROT_ALL );
    const auto Rsp = 0xFFFFFA0000000000 + 0x1000;
    uc_reg_write( Unicorn.get( ), UC_X86_REG_RSP, &Rsp );
    
    /* initialize the first parameter */
    const auto BlankPointer = nullptr;
    uc_reg_write( Unicorn.get( ), UC_X86_REG_RCX, &BlankPointer );

    /* allocate and save the initial cpu context */
    uc_context* Context;
    uc_context_alloc( Unicorn.get( ), &Context );
    uc_context_save( Unicorn.get( ), Context );

    const auto DumpImport = [ & ]( const std::uintptr_t Address )
    {
        /* restore the cpu context to the initial context */
        uc_context_restore( Unicorn.get( ), Context );

        /* start the emulation */
        uc_emu_start( Unicorn.get( ), Address, 0, 0, 0 );

        /* check if the exception is triggered by our trap */
        std::uint64_t Rax;
        uc_reg_read( Unicorn.get( ), UC_X86_REG_RAX, &Rax );
        if ( Rax == *reinterpret_cast< std::uint64_t* >( Vanguard ) )
        {
            /* read the import name's address */
            std::uintptr_t Rdx;
            uc_reg_read( Unicorn.get( ), UC_X86_REG_RDX, &Rdx );

            /* read and log the import name */
            char Name[ 0x20 ];
            uc_mem_read( Unicorn.get( ), Rdx, Name, sizeof( Name ) );
            std::cout << "set_name(0x" << std::hex << Address << ", \"LI::" << Name << "\"); \n";
        }
    };

    /* scan for all jump proxies */
    for ( auto PossibleImportJump : ud::module_t( Vanguard )[ ".text" ].find_patterns( "48 33 C4 48 89 45 ?? 48 8B D9 33 C9 E9" ) )
    {
        /* locate the start of the function */
        auto PossibleImport = ud::find_pattern_primitive< std::uint8_t* >( PossibleImportJump - 50, PossibleImportJump, "48 8B C4" );
		if ( !PossibleImport )
			PossibleImport = ud::find_pattern_primitive< std::uint8_t* >( PossibleImportJump - 50, PossibleImportJump, "48 89 54" );

        /* attempt to emulate the possible import */
        if ( PossibleImport )
            DumpImport( *PossibleImport - Vanguard );
    }

    return 0;
}