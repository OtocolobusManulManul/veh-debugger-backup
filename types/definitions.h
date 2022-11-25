#define WIN32_LEAN_AND_MEAN 

//target to inject into

#define TARGET ""

//symbol file to read from

#define SYMBOL_FILE "knownSymbols.dat"

//debug verbosity macros
//to see every indexed function
//set the dump macros to
//something absurdly high

#define FunctionDump 20
#define KnownSymbolDump 20

//VEH default verbosity settings

#define STACK_DUMP 24               // QWORDS to dump from the stack
#define SHOW_NAME true              // outputs name of function
#define SHOW_TRACE true             // outputs stack poiinter and calling fuction address
#define SHOW_GP true                // outputs general purpose registers
#define SHOW_FPU false              // shows floating point registers (not yet implemented because I am lazy)
#define SHOW_EFLAGS false           // outputs eflags
#define SHOW_SEGMENT_REGS false     // outputs segment registers
#define WATCH_ALL_EXCEPTIONS false  // prints alert when any exception is passed
