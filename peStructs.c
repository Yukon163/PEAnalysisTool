#ifndef YUKON_IMPORT
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <string.h>
    #include <stdint.h>
#endif

typedef struct _IMAGE_DOS_HEADER { 			// DOS .EXE header
    uint16_t e_magic; 							  // Magic number +0x0
    uint16_t e_cblp; 							  // Bytes on last page of file
    uint16_t e_cp; 							  	  // Pages in file
    uint16_t e_crlc; 							  // Relocations
    uint16_t e_cparhdr;							  // Size of header in paragraphs
    uint16_t e_minalloc; 						  // Minimum extra paragraphs needed
    uint16_t e_maxalloc; 						  // Maximum extra paragraphs needed
    uint16_t e_ss; 								 // Initial (relative) SS value
    uint16_t e_sp; 								 // Initial SP value
    uint16_t e_csum; 							 // Checksum
    uint16_t e_ip; 							     // Initial IP value
    uint16_t e_cs; 							     // Initial (relative) CS value
    uint16_t e_lfarlc; 							 // File address of relocation table
    uint16_t e_ovno; 							 // Overlay number
    uint16_t e_res[4]; 							 // Reserved words
    uint16_t e_oemid; 							 // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo; 						 // OEM information; e_oemid specific
    uint16_t e_res2[10]; 						 // Reserved words
    uint32_t  e_lfanew; 							 // 偏移为0x3C处存放pe文件头的偏移
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine; 				    // 运行平台
    uint16_t NumberOfSections; 			// 文件的区块数
    uint32_t TimeDateStamp; 			// 文件创建日期和时间
    uint32_t PointerToSymbolTable; 	// 指向符号表
    uint32_t NumberOfSymbols; 			// 符号表中符号数
    uint16_t SizeOfOptionalHeader; 		// IMAGE_OPTIONAL_HEADER结构的大小
    uint16_t Characteristics; 			// 文件属性
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress; // 内存虚拟地址
    uint32_t Size; // 长度
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER { // 32 位系统
    uint16_t    Magic;                       // 2 bytes
    uint8_t    MajorLinkerVersion;          // 1 byte
    uint8_t    MinorLinkerVersion;          // 1 byte
    uint32_t   SizeOfCode;                  // 4 bytes
    uint32_t   SizeOfInitializedData;       // 4 bytes
    uint32_t   SizeOfUninitializedData;     // 4 bytes
    uint32_t   AddressOfEntryPoint;         // 4 bytes
    uint32_t   BaseOfCode;                  // 4 bytes
    uint32_t   BaseOfData;                  // 4 bytes
    uint32_t   ImageBase;                   // 4 bytes
    uint32_t   SectionAlignment;            // 4 bytes
    uint32_t   FileAlignment;               // 4 bytes
    uint16_t    MajorOperatingSystemVersion; // 2 bytes
    uint16_t    MinorOperatingSystemVersion; // 2 bytes
    uint16_t    MajorImageVersion;           // 2 bytes
    uint16_t    MinorImageVersion;           // 2 bytes
    uint16_t    MajorSubsystemVersion;       // 2 bytes
    uint16_t    MinorSubsystemVersion;       // 2 bytes
    uint32_t   Win32VersionValue;           // 4 bytes
    uint32_t   SizeOfImage;                 // 4 bytes
    uint32_t   SizeOfHeaders;               // 4 bytes
    uint32_t   CheckSum;                    // 4 bytes
    uint16_t    Subsystem;                   // 2 bytes
    uint16_t    DllCharacteristics;          // 2 bytes
    uint32_t   SizeOfStackReserve;          // 4 bytes
    uint32_t   SizeOfStackCommit;           // 4 bytes
    uint32_t   SizeOfHeapReserve;           // 4 bytes
    uint32_t   SizeOfHeapCommit;            // 4 bytes
    uint32_t   LoaderFlags;                 // 4 bytes
    uint32_t   NumberOfRvaAndSizes;         // 4 bytes
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // 偏移0x78 16 x 8 bytes = 128 bytes
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t Name[8];               // 区块名，8字节
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize; 		// 区块的实际大小(对齐前)
    } Misc;
    uint32_t VirtualAddress; 		// 区块载入内存中的RVA
    uint32_t SizeOfRawData; 		// 区块在物理文件中所占用空间(对齐后)
    uint32_t PointerToRawData; 	    // 区块在物理文件中的偏移
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics; 	// 属性
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk; 		// RVA，指向INT
    } DUMMYUNIONNAME;
    uint32_t TimeDateStamp; 			// 时间戳，可以忽略
    uint32_t ForwarderChain; 			// 很少使用
    uint32_t Name;					    // RVA，指向DLL名的字符串
    uint32_t FirstThunk; 				// RVA，指向IAT
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        uint32_t ForwarderString; 	 // 指向中转字符串的RVA
        uint32_t Function; 		// RVA，被输入函数的内存地址
        uint32_t Ordinal; 			// 被输入函数的序号，历史遗留问题
        uint32_t AddressOfData; 	 // RVA，指向IMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;		// 历史遗留问题，通常设置为0
    char Name[1]; 	// RVA，指向函数名的字符串
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;				// 0 * 8
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;					// 0 * 4
    uint16_t MinorVersion;					// 0 * 4
    uint32_t Name;							// pe文件模块名称RVA
    uint32_t Base;
    uint32_t NumberOfFunctions;			 // AddressOfFunctions元素个数
    uint32_t NumberOfNames;				 // AddressOfNames元素个数
    uint32_t AddressOfFunctions;			 // 导出函数地址表 RVA（EAT）
    uint32_t AddressOfNames;				 // 函数名称表 RVA（ENT）
    uint32_t AddressOfNameOrdinals;		 // 名称对应的 ordinal 表 RVA（EOT）
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

void print_header_item(size_t offset, const char *name, uint64_t value) {
    printf("0x%-4zX  %-31s    0x%-8llX\n", offset, name, value);
}

void traverse_dos_header(const IMAGE_DOS_HEADER *dos) {
    printf("\nIMAGE_DOS_HEADER (DOS .EXE header):\n");
    size_t offset = 0;

    print_header_item(offset, "e_magic", dos->e_magic);
    offset += sizeof(dos->e_magic);

    print_header_item(offset, "e_cblp", dos->e_cblp);
    offset += sizeof(dos->e_cblp);

    print_header_item(offset, "e_cp", dos->e_cp);
    offset += sizeof(dos->e_cp);

    print_header_item(offset, "e_crlc", dos->e_crlc);
    offset += sizeof(dos->e_crlc);

    print_header_item(offset, "e_cparhdr", dos->e_cparhdr);
    offset += sizeof(dos->e_cparhdr);

    print_header_item(offset, "e_minalloc", dos->e_minalloc);
    offset += sizeof(dos->e_minalloc);

    print_header_item(offset, "e_maxalloc", dos->e_maxalloc);
    offset += sizeof(dos->e_maxalloc);

    print_header_item(offset, "e_ss", dos->e_ss);
    offset += sizeof(dos->e_ss);

    print_header_item(offset, "e_sp", dos->e_sp);
    offset += sizeof(dos->e_sp);

    print_header_item(offset, "e_csum", dos->e_csum);
    offset += sizeof(dos->e_csum);

    print_header_item(offset, "e_ip", dos->e_ip);
    offset += sizeof(dos->e_ip);

    print_header_item(offset, "e_cs", dos->e_cs);
    offset += sizeof(dos->e_cs);

    print_header_item(offset, "e_lfarlc", dos->e_lfarlc);
    offset += sizeof(dos->e_lfarlc);

    print_header_item(offset, "e_ovno", dos->e_ovno);
    offset += sizeof(dos->e_ovno);

    for (int i = 0; i < 4; i++) {
        char name[16];
        snprintf(name, sizeof(name), "e_res[%d]", i);
        print_header_item(offset, name, dos->e_res[i]);
        offset += sizeof(dos->e_res[i]);
    }

    print_header_item(offset, "e_oemid", dos->e_oemid);
    offset += sizeof(dos->e_oemid);

    print_header_item(offset, "e_oeminfo", dos->e_oeminfo);
    offset += sizeof(dos->e_oeminfo);

    for (int i = 0; i < 10; i++) {
        char name[16];
        snprintf(name, sizeof(name), "e_res2[%d]", i);
        print_header_item(offset, name, dos->e_res2[i]);
        offset += sizeof(dos->e_res2[i]);
    }

    print_header_item(offset, "e_lfanew", dos->e_lfanew);
}

void traverse_file_header(const IMAGE_FILE_HEADER *file) {
    printf("\nIMAGE_FILE_HEADER:\n");
    size_t offset = 0;

    print_header_item(offset, "Machine", file->Machine);
    offset += sizeof(file->Machine);

    print_header_item(offset, "NumberOfSections", file->NumberOfSections);
    offset += sizeof(file->NumberOfSections);

    print_header_item(offset, "TimeDateStamp", file->TimeDateStamp);
    offset += sizeof(file->TimeDateStamp);

    print_header_item(offset, "PointerToSymbolTable", file->PointerToSymbolTable);
    offset += sizeof(file->PointerToSymbolTable);

    print_header_item(offset, "NumberOfSymbols", file->NumberOfSymbols);
    offset += sizeof(file->NumberOfSymbols);

    print_header_item(offset, "SizeOfOptionalHeader", file->SizeOfOptionalHeader);
    offset += sizeof(file->SizeOfOptionalHeader);

    print_header_item(offset, "Characteristics", file->Characteristics);
}

void traverse_optional_header(const IMAGE_OPTIONAL_HEADER *opt) {
    printf("\nIMAGE_OPTIONAL_HEADER:\n");
    size_t offset = 0;

    print_header_item(offset, "Magic", opt->Magic);
    offset += sizeof(opt->Magic);

    print_header_item(offset, "MajorLinkerVersion", opt->MajorLinkerVersion);
    offset += sizeof(opt->MajorLinkerVersion);

    print_header_item(offset, "MinorLinkerVersion", opt->MinorLinkerVersion);
    offset += sizeof(opt->MinorLinkerVersion);

    print_header_item(offset, "SizeOfCode", opt->SizeOfCode);
    offset += sizeof(opt->SizeOfCode);

    print_header_item(offset, "SizeOfInitializedData", opt->SizeOfInitializedData);
    offset += sizeof(opt->SizeOfInitializedData);

    print_header_item(offset, "SizeOfUninitializedData", opt->SizeOfUninitializedData);
    offset += sizeof(opt->SizeOfUninitializedData);

    print_header_item(offset, "AddressOfEntryPoint", opt->AddressOfEntryPoint);
    offset += sizeof(opt->AddressOfEntryPoint);

    print_header_item(offset, "BaseOfCode", opt->BaseOfCode);
    offset += sizeof(opt->BaseOfCode);

    print_header_item(offset, "BaseOfData", opt->BaseOfData);
    offset += sizeof(opt->BaseOfData);

    print_header_item(offset, "ImageBase", opt->ImageBase);
    offset += sizeof(opt->ImageBase);

    print_header_item(offset, "SectionAlignment", opt->SectionAlignment);
    offset += sizeof(opt->SectionAlignment);

    print_header_item(offset, "FileAlignment", opt->FileAlignment);
    offset += sizeof(opt->FileAlignment);

    print_header_item(offset, "MajorOperatingSystemVersion", opt->MajorOperatingSystemVersion);
    offset += sizeof(opt->MajorOperatingSystemVersion);

    print_header_item(offset, "MinorOperatingSystemVersion", opt->MinorOperatingSystemVersion);
    offset += sizeof(opt->MinorOperatingSystemVersion);

    print_header_item(offset, "MajorImageVersion", opt->MajorImageVersion);
    offset += sizeof(opt->MajorImageVersion);

    print_header_item(offset, "MinorImageVersion", opt->MinorImageVersion);
    offset += sizeof(opt->MinorImageVersion);

    print_header_item(offset, "MajorSubsystemVersion", opt->MajorSubsystemVersion);
    offset += sizeof(opt->MajorSubsystemVersion);

    print_header_item(offset, "MinorSubsystemVersion", opt->MinorSubsystemVersion);
    offset += sizeof(opt->MinorSubsystemVersion);

    print_header_item(offset, "Win32VersionValue", opt->Win32VersionValue);
    offset += sizeof(opt->Win32VersionValue);

    print_header_item(offset, "SizeOfImage", opt->SizeOfImage);
    offset += sizeof(opt->SizeOfImage);

    print_header_item(offset, "SizeOfHeaders", opt->SizeOfHeaders);
    offset += sizeof(opt->SizeOfHeaders);

    print_header_item(offset, "CheckSum", opt->CheckSum);
    offset += sizeof(opt->CheckSum);

    print_header_item(offset, "Subsystem", opt->Subsystem);
    offset += sizeof(opt->Subsystem);

    print_header_item(offset, "DllCharacteristics", opt->DllCharacteristics);
    offset += sizeof(opt->DllCharacteristics);

    print_header_item(offset, "SizeOfStackReserve", opt->SizeOfStackReserve);
    offset += sizeof(opt->SizeOfStackReserve);

    print_header_item(offset, "SizeOfStackCommit", opt->SizeOfStackCommit);
    offset += sizeof(opt->SizeOfStackCommit);

    print_header_item(offset, "SizeOfHeapReserve", opt->SizeOfHeapReserve);
    offset += sizeof(opt->SizeOfHeapReserve);

    print_header_item(offset, "SizeOfHeapCommit", opt->SizeOfHeapCommit);
    offset += sizeof(opt->SizeOfHeapCommit);

    print_header_item(offset, "LoaderFlags", opt->LoaderFlags);
    offset += sizeof(opt->LoaderFlags);

    print_header_item(offset, "NumberOfRvaAndSizes", opt->NumberOfRvaAndSizes);
    offset += sizeof(opt->NumberOfRvaAndSizes);

    printf("\nIMAGE_DATA_DIRECTORY:\n");
    for (int i = 0; i < 16; i++) {
        char name[32];
        snprintf(name, sizeof(name), "DataDirectory[%d].VirtualAddress", i);
        print_header_item(offset, name, opt->DataDirectory[i].VirtualAddress);
        offset += sizeof(opt->DataDirectory[i].VirtualAddress);

        snprintf(name, sizeof(name), "DataDirectory[%d].Size", i);
        print_header_item(offset, name, opt->DataDirectory[i].Size);
        offset += sizeof(opt->DataDirectory[i].Size);
    }
}

void traverse_nt_headers(const IMAGE_NT_HEADERS *nt) {
    printf("\nIMAGE_NT_HEADERS:");
    size_t offset = 0;
    printf("\n0x%-4zX  %-31s    0x%-8llX", offset, "Signature", (uint64_t)nt->Signature);
    offset += sizeof(nt->Signature);

    printf("\n0x%-4zX  %-31s", offset, "IMAGE_FILE_HEADER");
    offset += sizeof(nt->FileHeader);

    printf("\n0x%-4zX  %-31s\n", offset, "IMAGE_OPTIONAL_HEADER");

    traverse_file_header(&nt->FileHeader);
    traverse_optional_header(&nt->OptionalHeader);
}

void traverse_pe_headers(const IMAGE_DOS_HEADER *dos) {
    traverse_dos_header(dos);

    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS*)((const uint8_t*)dos + dos->e_lfanew);
    traverse_nt_headers(nt);
}

void print_section_item(uint32_t value, const char *name) {
    printf("        %-24s 0x%-8lX\n", name, value);
}

void traverse_sections_table(char *peContent, const long sectionTableOffset, int NumberOfSections) {
    printf("IMAGE_SECTION_HEADERs (%d sections):", NumberOfSections);

    IMAGE_SECTION_HEADER *sectionHeaders = (IMAGE_SECTION_HEADER*)(peContent + sectionTableOffset);

    for (int i = 0; i < NumberOfSections; i++) {
        printf("\n[Section %d]\n", i + 1);

        // 打印节区名（确保以null结尾）
        char sectionName[9] = {0};
        memcpy(sectionName, sectionHeaders[i].Name, 8);
        printf("0x%-4zX  %-24s %-8s\n",
               sectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER),
               "Name",
               sectionName);

        print_section_item(sectionHeaders[i].Misc.VirtualSize, "VirtualSize");
        print_section_item(sectionHeaders[i].VirtualAddress, "VirtualAddress");
        print_section_item(sectionHeaders[i].SizeOfRawData, "SizeOfRawData");
        print_section_item(sectionHeaders[i].PointerToRawData, "PointerToRawData");
        print_section_item(sectionHeaders[i].PointerToRelocations, "PointerToRelocations");
        print_section_item(sectionHeaders[i].PointerToLinenumbers, "PointerToLinenumbers");
        print_section_item(sectionHeaders[i].NumberOfRelocations, "NumberOfRelocations");
        print_section_item(sectionHeaders[i].NumberOfLinenumbers, "NumberOfLinenumbers");
        print_section_item(sectionHeaders[i].Characteristics, "Characteristics");
    }
}

uint32_t RVAToFOA(uint32_t rva, IMAGE_SECTION_HEADER *sectionHeaders, int numberOfSections, int showInfo) {
    for (int i = 0; i < numberOfSections; i++) {
        uint32_t sectionVA = sectionHeaders[i].VirtualAddress;
        uint32_t sectionSize = sectionHeaders[i].Misc.VirtualSize;
        uint32_t sectionFOA = sectionHeaders[i].PointerToRawData;

        if (rva >= sectionVA && rva < sectionVA + sectionSize) {
            char sectionName[9] = {0};
            memcpy(sectionName, sectionHeaders[i].Name, 8);
            if (showInfo) {
                printf("\nthe RVA is at %-8s\n", sectionName);
                printf("RVA 0x%08X -> FOA 0x%08X\n", rva, sectionFOA + (rva - sectionVA));
            }
            return sectionFOA + (rva - sectionVA);
        }
    }
    return rva;
}

uint32_t FOAToRVA(uint32_t foa, IMAGE_SECTION_HEADER *sectionHeaders, int numberOfSections, int showInfo) {
    for (int i = 0; i < numberOfSections; i++) {
        uint32_t sectionFOA = sectionHeaders[i].PointerToRawData;
        uint32_t sectionSizeRaw = sectionHeaders[i].SizeOfRawData;
        uint32_t sectionVA = sectionHeaders[i].VirtualAddress;

        if (foa >= sectionFOA && foa < sectionFOA + sectionSizeRaw) {
            char sectionName[9] = {0};
            memcpy(sectionName, sectionHeaders[i].Name, 8);
            if (showInfo) {
                printf("\nthe FOA is at %-8s\n", sectionName);
                printf("FOA 0x%08X -> RVA 0x%08X\n", foa, sectionVA + (foa - sectionFOA));
            }
            return sectionVA + (foa - sectionFOA);
        }
    }
    return foa;
}

void traverse_import_table(char *peContent, uint32_t importTableFOA, IMAGE_SECTION_HEADER *sectionHeaders, int numberOfSections) {
    if (importTableFOA == 0) {
        printf("No import table found.\n");
        return;
    }
    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)(peContent + importTableFOA);

    while (importDesc->OriginalFirstThunk != 0 || importDesc->FirstThunk != 0) {
        uint32_t dllNameFOA = RVAToFOA(importDesc->Name, sectionHeaders, numberOfSections, 0);
        printf("DLL: %s\n", peContent + dllNameFOA);

        IMAGE_THUNK_DATA32 *thunk = (IMAGE_THUNK_DATA32 *)(peContent + RVAToFOA(importDesc->OriginalFirstThunk, sectionHeaders, numberOfSections, 0));

        while (thunk->u1.AddressOfData != 0) {
            IMAGE_IMPORT_BY_NAME *importByName = (IMAGE_IMPORT_BY_NAME *)(peContent + RVAToFOA(thunk->u1.AddressOfData, sectionHeaders, numberOfSections, 0));
            printf("  Function: %s\n", importByName->Name);
            thunk++;
        }
        printf("\n");
        importDesc++;
    }
}

void traverse_export_table(char *peContent, uint32_t exportTableFOA, IMAGE_SECTION_HEADER *sectionHeaders, int numberOfSections) {
    if (exportTableFOA == 0) {
        printf("No export table found.\n");
        return;
    }

    IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)(peContent + exportTableFOA);

    // 解析模块名称
    uint32_t nameFOA = RVAToFOA(exportDir->Name, sectionHeaders, numberOfSections, 0);
    printf("Export Module Name: %s\n", peContent + nameFOA);
    printf("Base Ordinal: %u\n", exportDir->Base);
    printf("Number of Functions: %u\n", exportDir->NumberOfFunctions);
    printf("Number of Names: %u\n\n", exportDir->NumberOfNames);

    // 表的地址换算成FOA
    uint32_t functionsFOA = RVAToFOA(exportDir->AddressOfFunctions, sectionHeaders, numberOfSections, 0);
    uint32_t namesFOA = RVAToFOA(exportDir->AddressOfNames, sectionHeaders, numberOfSections, 0);
    uint32_t ordinalsFOA = RVAToFOA(exportDir->AddressOfNameOrdinals, sectionHeaders, numberOfSections, 0);

    uint32_t *functionRVAs = (uint32_t *)(peContent + functionsFOA);
    uint32_t *nameRVAs = (uint32_t *)(peContent + namesFOA);
    uint16_t *ordinals = (uint16_t *)(peContent + ordinalsFOA);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
        uint32_t nameRVA = nameRVAs[i];
        uint32_t nameFOA = RVAToFOA(nameRVA, sectionHeaders, numberOfSections, 0);
        const char *funcName = peContent + nameFOA;

        uint16_t ordinal = ordinals[i]; // 实际上是索引到 AddressOfFunctions 中的偏移
        uint32_t funcRVA = functionRVAs[ordinal];

        printf("  Function Name: %-30s Ordinal: %4u RVA: 0x%08X\n", funcName, exportDir->Base + ordinal, funcRVA);
    }
}

