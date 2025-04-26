#ifndef YUKON_IMPORT
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdint.h>
#endif

#include "peStructs.c"

long getPE(char *peName, char **peContent) {
    size_t len = strlen(peName);
    if (len > 0 && peName[len - 1] == '\n') {
        peName[len - 1] = '\0';
    }
    FILE * pPE = fopen(peName, "rb");
    if (pPE == NULL) {
        printf("Error opening file\n");
        exit(0);
    }

    fseek(pPE, 0, SEEK_END);
    long size = ftell(pPE);
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        perror("File is too small");
        exit(0);
    }
    fseek(pPE, 0, SEEK_SET);

    *peContent = (char *)malloc(size);
    if (*peContent == NULL) {
        perror("Memory allocation failed");
        exit(0);
    }

    fread(*peContent, 1, size, pPE);
    fclose(pPE);

    return size;
}


void printInHex(char *peContent, long peSize, long start, long size, int withOffset) {
    if (start + size > peSize) {
        printf("Overflow? wt are you printing?\n");
        exit(0);
    }
    printf("          ");
    for (int i = 0; i < 8; i++)
        printf("%2x ", i);
    for (int i = 8; i < 16; i++)
        printf(" %2x", i);
    for (long i = start; i < start + size; i++) {
        if (i % 16 == 0 || (i == start && start != 0)) {
            printf("\n");
            if(withOffset == 1) {
                printf("%08lx  ", i);
            }
            if (i == start && start != 0) {
                for (int j = 0; j < (i % 16> 8?8:i % 16); j++) {
                    printf("   ");
                }
                printf(" ");
                for (int j = 8; j < i % 16; j++) {
                    printf("   ");
                }
            }
        } else if (i % 8 == 0) {
            printf(" ");
        }
        printf("%02x ", (unsigned char)peContent[i]);
    }
    printf("\n");
}

unsigned long getOffsetValueFromType(const char *peContent, long offset, size_t typeBytes) {
    unsigned long result = 0;

    // 确保在小端序下读取（Windows PE 文件是小端）
    for (size_t i = 0; i < typeBytes; i++) {
        result |= ((unsigned long)(unsigned char)peContent[offset + i]) << (8 * i);
    }

    return result;
    }


int main() {
    char choice[5];
    char *peContent = NULL;
    char peName[260];

    printf("Welcome to the Yukon's PE Analysis Tool\n");
    printf("Drag your file here: ");
    if (fgets(peName, sizeof(peName), stdin) == NULL) {
        perror("Input error");
        return 1;
    }

    long PESize = getPE(peName, &peContent);
    printf("size of pe: 0x%lx\n", PESize);
    const IMAGE_DOS_HEADER *pDosHeader = (const IMAGE_DOS_HEADER *)peContent;
    IMAGE_NT_HEADERS *pNTHeader = (IMAGE_NT_HEADERS *)((const uint8_t*)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_FILE_HEADER *pFileHeader = &pNTHeader->FileHeader;
    IMAGE_OPTIONAL_HEADER *pOptionalHeader = &pNTHeader->OptionalHeader;
    if (pNTHeader->OptionalHeader.Magic != 0x10b) {
        printf("this tools can only analysis 32-bit pe, pls wait for upgrade\n");
        exit(0);
    }

    printf("Frist step: get NT header from ms-dos_HEADER\n");
    printf("IMAGE_DOS_HEADER.e_lfanew = 0x%lx\n", pDosHeader->e_lfanew);
    printf("show the content of them?(yes/no)");
    scanf("%4s", choice);
    if (strcmp(choice, "yes") == 0 || strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
        traverse_pe_headers(pDosHeader);
        printf("\n");
    }

    printf("Second step: get section_table from caculated offset\n");
    int numberOfSections = pFileHeader->NumberOfSections;
    printf("before get the table, we might need the number of sections from IMAGE_FILE_HEADER.NumberOfSections:\n");
    const long sectionTableOffset = (long)pDosHeader->e_lfanew+0x4+0x14+0xe0;
    printf("then, we get the offset of Section table: 0x%lx\n", sectionTableOffset);
    printf("show the content of Section table?(yes/no)");
    scanf("%4s", choice);
    if (strcmp(choice, "yes") == 0 || strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
        traverse_sections_table(peContent, sectionTableOffset, numberOfSections);
        printf("\n");
    }

    IMAGE_SECTION_HEADER *sectionHeaders = (IMAGE_SECTION_HEADER*)(peContent + sectionTableOffset);
    printf("Third step, get the export table from :IMAGE_OPTIONAL_HEADER->DataDirectory[0].VirtualAddress\n");
    long exportTableRVA = (long)pOptionalHeader->DataDirectory[0].VirtualAddress;
    uint32_t exportTableFOA = RVAToFOA(exportTableRVA, sectionHeaders, numberOfSections, 0);
    printf("show the content of export table?(yes/no)");
    scanf("%4s", choice);
    if (strcmp(choice, "yes") == 0 || strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
        traverse_export_table(peContent, exportTableFOA, sectionHeaders, numberOfSections);
        printf("\n");
    }

    printf("Last step, get the import table from :IMAGE_OPTIONAL_HEADER->DataDirectory[1].VirtualAddress\n");
    long importTableRVA = (long)pOptionalHeader->DataDirectory[1].VirtualAddress;
    uint32_t importTableFOA = RVAToFOA(importTableRVA, sectionHeaders, numberOfSections, 0);
    printf("show the content of import table?(yes/no)");
    scanf("%4s", choice);
    if (strcmp(choice, "yes") == 0 || strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
        traverse_import_table(peContent, importTableFOA, sectionHeaders, numberOfSections);
    }

    printf("Thank you for using Yukon's PE Analysis Tool!\n");

    free(peContent);

    return 0;
}



