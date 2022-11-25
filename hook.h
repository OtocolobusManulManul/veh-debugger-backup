#define WIN32_LEAN_AND_MEAN

/*
void generic_hook(PCONTEXT ctx)
{

    //access args in this order
    DWORD64 * stackptr = reinterpret_cast<DWORD64 *>(ctx->Rsp);
    
    ctx->Rcx = 1;
    ctx->Rdx = 2;        
    ctx->R8 = 3;
    ctx->R9 = 4;
    *(stackptr + 5) = 5;
    *(stackptr + 6) = 6;
    

}
*/

void InitializeHooks () 
{
    //do the thing here
}
