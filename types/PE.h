#define WIN32_LEAN_AND_MEAN

//implicit exception dir indexing

#define EXCEPTION_DIR_ENTRY 12
#define BeginAddress 0
#define EndAddresss 4
#define UnwindUnion 8


class _NT_SECTION_HEADER_DATA
{
    public:

        uintptr_t ProcAddress;
        PIMAGE_SECTION_HEADER SECTION_HEADER;

        _NT_SECTION_HEADER_DATA() {}

        _NT_SECTION_HEADER_DATA(HMODULE hMod, PIMAGE_SECTION_HEADER header)
        {
            SECTION_HEADER = header;    
            uintptr_t HmodCast = reinterpret_cast<uintptr_t>(hMod);
            ProcAddress = HmodCast + (int) header->VirtualAddress;
        }

};

class _NT_HEADERS 
{

    #define dTEXT  53629 //TEXT macro is implemented somewhere else in headers
    #define DATA   44390
    #define IDATA  55415
    #define DIDAT  56006
    #define RSRC   51134
    #define RELOC  59099
    #define PDATA  56934
    #define _RDATA 35879
    #define RDATA  57386

    public:

        _NT_HEADERS () {} 

        _NT_HEADERS (HMODULE hMod) 
        {
            HmodCast = reinterpret_cast<uintptr_t>(hMod);
            ModuleBaseAddr = hMod;
        }

        HMODULE ModuleBaseAddr;
        uintptr_t HmodCast;

        _NT_SECTION_HEADER_DATA text; 
        _NT_SECTION_HEADER_DATA data;
        _NT_SECTION_HEADER_DATA idata;
        _NT_SECTION_HEADER_DATA didat;
        _NT_SECTION_HEADER_DATA rsrc;
        _NT_SECTION_HEADER_DATA reloc;
        _NT_SECTION_HEADER_DATA pdata;
        _NT_SECTION_HEADER_DATA _rdata;
        _NT_SECTION_HEADER_DATA rdata;

        void SetNTHeader(PIMAGE_SECTION_HEADER Section)
        {

            //squared to add variability
            int NameHash = 0;
            BYTE * name = Section->Name;
            while (*name) {NameHash = NameHash + ((int) (*name)) * ((int) (*name)); name ++;}
        
            switch (NameHash)
            {
                case dTEXT:
                    //printf("text: ");
                    text = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;
                
                case DATA:
                    //printf("data: ");
                    data = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case IDATA:
                    //printf("idata: ");
                    idata = _NT_SECTION_HEADER_DATA(ModuleBaseAddr,Section);
                    break;

                case DIDAT:
                    //printf("didata: ");
                    didat = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case RSRC:
                    //printf("RSRC: ");
                    rsrc = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case RELOC:
                    //printf("reloc: ");
                    reloc = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case PDATA:
                    //printf("pdata: ");
                    pdata = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case RDATA:
                    //printf("rdata: ");
                    rdata = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                case _RDATA:
                    //printf("_RDATA: ");
                    _rdata = _NT_SECTION_HEADER_DATA(ModuleBaseAddr, Section);
                    break;

                default:
                    break;
            }
            
        }

};