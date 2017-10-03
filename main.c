/******************************************************************************

  The MIT License (MIT)

  Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

******************************************************************************/

/** ***************************************************************************
 * @file main.c
 * @brief The VMX benchmark (VMXbench)
 * @copyright Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)
 * @license The MIT License (http://opensource.org/licenses/MIT)
 *************************************************************************** */

#include <stdint.h>

/** ***************************************************************************
 * @section section_uefi Section 1. UEFI definitions
 * This section contains several basic UEFI type and function definitions.
 *************************************************************************** */

#define IN
#define OUT
#define EFIAPI

typedef unsigned short CHAR16, UINT16;
typedef unsigned long long EFI_STATUS;
typedef void *EFI_HANDLE;

static const EFI_STATUS EFI_SUCCESS = 0;
static const EFI_STATUS EFI_NOT_READY = 0x8000000000000006;

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;
typedef
EFI_STATUS
(EFIAPI *EFI_INPUT_READ_KEY) (
    IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
    OUT EFI_INPUT_KEY *Key
    );
struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    void               *a;
    EFI_INPUT_READ_KEY ReadKeyStroke;
};

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef
EFI_STATUS
(EFIAPI *EFI_TEXT_STRING) (
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    IN CHAR16                          *String
    );
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void            *a;
    EFI_TEXT_STRING OutputString;
};

typedef struct {
    char                            a[36];
    EFI_HANDLE                      ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *ConIn;
    EFI_HANDLE                      ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
} EFI_SYSTEM_TABLE;

EFI_SYSTEM_TABLE  *SystemTable;

CHAR16 getwchar()
{
    EFI_STATUS status;
    EFI_INPUT_KEY key;

    do {
	status = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &key);
    } while (status == EFI_NOT_READY);
    return key.UnicodeChar;
}

void putws(CHAR16 *str)
{
    SystemTable->ConOut->OutputString(SystemTable->ConOut, str);
}

void putchar_buffered(CHAR16 c)
{
    const int BUFSIZE = 1024;
    CHAR16 buf[BUFSIZE];
    static int index = 0;

    buf[index++] = c;
    if (index == BUFSIZE - 1 || c == L'\n' || c == L'\0') {
	buf[index] = L'\0';
	putws(buf);
	index = 0;
    }
}

void wprintf (const CHAR16 *format, ...)
{
    __builtin_va_list va_list;
    __builtin_va_start(va_list, format);
    for (CHAR16 c = *format; (c = *format++) != L'\0';) {
	if (c != L'%') {
	    putchar_buffered(c);
	    continue;
	}

	CHAR16 prefix;
	c = *format++;
	if (c == L'0') {
	    prefix = L'0';
	    c = *format++;
	} else
	    prefix = L' ';

	int len;
	if (L'1' <= c && c <= L'9') {
	    len = c - L'0';
	    c = *format++;
	} else
	    len = 1;

	if (L'0' <= c && c <= L'9') {
	    len = len * 10 + (c - L'0');
	    c = *format++;
	}

	uint64_t arg = __builtin_va_arg(va_list, uint64_t);
	if (c == L's') {
	    CHAR16 *str = (CHAR16 *)arg;
	    while (*str != L'\0')
		putchar_buffered(*str++);
	    continue;
	}

	int base, digit;
	uint64_t divisor;
	if (c == L'd') {
	    base = 10;
	    digit = 20;
	    divisor = 10000000000000000000ULL;
	} else if (c == L'x') {
	    base = 16;
	    digit = 16;
	    divisor = 0x1000000000000000ULL;
	} else
	    continue; // not supported yet

	int start_output = 0, end_prefix = 0;
	for (; digit > 0; digit--) {
	    int q = arg / divisor;
	    arg %= divisor;

	    CHAR16 c = (q > 9 ? L'a' - 10 : L'0') + q;
	    if (start_output == 0)
		if (c != L'0' || digit <= len)
		    start_output = 1;
	    if (start_output == 1) {
		if (end_prefix == 0)
		    if (c != L'0' || digit == 1)
			end_prefix = 1;
		if (end_prefix == 0)
		    c = prefix;
		putchar_buffered(c);
	    }
	    divisor /= base;
	}
    }
    putchar_buffered(L'\0');
    __builtin_va_end(va_list);
}

/** ***************************************************************************
 * @section section_vmx Section 2. VMX definitions
 * This section contains several basic VMX function definitions.
 *************************************************************************** */

static inline uint64_t rdmsr(uint32_t index)
{
    uint32_t eax, edx;
    asm volatile ("rdmsr"
		  : "=a" (eax), "=d" (edx)
		  : "c" (index));
    return ((uint64_t)edx << 32) | eax;
}

static inline void wrmsr(uint32_t index, uint64_t value)
{
    uint32_t eax, edx;
    eax = value & 0xffffffff;
    edx = value >> 32;
    asm volatile ("wrmsr"
		  : 
		  : "c" (index), "a" (eax), "d" (edx));
}

static inline uint32_t vmread(uint32_t index)
{
    uint32_t value;
    asm volatile ("vmread %%rax, %%rdx"
		  : "=d" (value)
		  : "a" (index)
		  : "cc");
    return value;
}

static inline void vmwrite(uint32_t index, uint64_t value)
{
    asm volatile ("vmwrite %%rdx, %%rax"
		  :
		  : "a" (index), "d" (value)
		  : "cc", "memory");
}

static inline uint64_t rdtsc(void)
{
    uint32_t eax, edx;
    asm volatile ("rdtsc" : "=a"(eax), "=d"(edx));
    return (uint64_t)edx << 32 | (uint64_t)eax;
}

static inline uint64_t vmcall(uint64_t arg)
{
    uint64_t ret;
    asm volatile ("vmcall"
		  : "=a" (ret)
		  : "c" (arg)
		  : "memory", "rdx", "r8", "r9", "r10", "r11");
    return ret;
}

/** ***************************************************************************
 * @section section_vmxbench Section 3. VMXbench
 * This section contains VMXbench main functions
 *************************************************************************** */

static int env[28];
static int index;
static uint64_t tsc_exit[10], tsc_entry[10];

void print_results()
{
    uint64_t exit_min = UINT64_MAX, entry_min = UINT64_MAX, exit_max = 0, entry_max = 0;
    uint64_t exit_avg = 0, entry_avg = 0;

    for (int i = 0; i < 10; i++) {
	wprintf(L"VM exit[%d]: %5d, VM entry[%d]: %5d\r\n", i, tsc_exit[i], i, tsc_entry[i]);
	if (tsc_exit[i] < exit_min) exit_min = tsc_exit[i];
	if (tsc_exit[i] > exit_max) exit_max = tsc_exit[i];
	exit_avg += tsc_exit[i];
	if (tsc_entry[i] < entry_min) entry_min = tsc_entry[i];
	if (tsc_entry[i] > entry_max) entry_max = tsc_entry[i];
	entry_avg += tsc_entry[i];
    }
    wprintf(L"VM exit : min = %5d, max = %5d, avg = %5d\r\n", exit_min, exit_max, exit_avg / 10);
    wprintf(L"VM entry: min = %5d, max = %5d, avg = %5d\r\n", entry_min, entry_max, entry_avg / 10);
}

void print_exitreason(uint64_t reason)
{
    uint64_t q = vmread(0x6400);
    uint64_t rip = vmread(0x681E);
    uint64_t rsp = vmread(0x681C);
    wprintf(L"Unexpected VM exit: reason=%x, qualification=%x\r\n", reason, q);
    wprintf(L"rip: %08x, rsp: %08x\r\n", rip, rsp);
    for (int i = 0; i < 16; i++, rip++)
	wprintf(L"%02x ", *(uint8_t *)rip);
    wprintf(L"\r\n");
    for (int i = 0; i < 16; i++, rsp += 8)
	wprintf(L"%016x: %016x\r\n", rsp, *(uint64_t *)rsp);
    wprintf(L"\r\n");
}

uint64_t host_entry(uint64_t arg)
{
    tsc_exit[index] = rdtsc() - arg;
    uint64_t reason = vmread(0x4402);
    if (reason == 18) {
	if (arg > 0) {
	    uint64_t rip = vmread(0x681E); // Guest RIP
	    uint64_t len = vmread(0x440C); // VM-exit instruction length
	    vmwrite(0x681E, rip + len);
	    return rdtsc();
	}
	print_results();
    } else
	print_exitreason(reason);

    __builtin_longjmp(env, 1);
}

void __host_entry(void);
void _host_entry(void)
{
    asm volatile (
	"__host_entry:\n\t"
	"call host_entry\n\t"
	"vmresume\n\t"
	"loop: jmp loop\n\t"
	);
}

_Noreturn
void guest_entry(void)
{
    // warm up
    for (int i = 0; i < 10; i++)
	vmcall(1);
    // benchmark
    for (index = 0; index < 10; index++) {
	uint64_t tsc;
	tsc = vmcall(rdtsc());
	tsc = rdtsc() - tsc;
	tsc_entry[index] = tsc;
    }
    vmcall(0);
    while(1);
}

struct registers {
    uint16_t cs, ds, es, fs, gs, ss, tr, ldt;
    uint32_t rflags;
    uint64_t cr0, cr3, cr4;
    uint64_t ia32_efer, ia32_feature_control;
    struct {
	uint16_t limit;
	uint64_t base;
    } __attribute__((packed)) gdt, idt;
    // attribute "packed" requires -mno-ms-bitfields
};

void save_registers(struct registers *regs)
{
    asm volatile ("mov %%cr0, %0" : "=r" (regs->cr0));
    asm volatile ("mov %%cr3, %0" : "=r" (regs->cr3));
    asm volatile ("mov %%cr4, %0" : "=r" (regs->cr4));
    regs->ia32_efer = rdmsr(0xC0000080);
    asm volatile ("pushf; pop %%rax" : "=a" (regs->rflags));
    asm volatile ("mov %%cs, %0" : "=m" (regs->cs));
}

void print_registers(struct registers *regs)
{
    wprintf(L"CR0: %016x, CR3: %016x, CR4: %016x\n", regs->cr0, regs->cr3, regs->cr4);
    wprintf(L"RFLAGS: %016x\n", regs->rflags);
    wprintf(L"CS: %04x\n", regs->cs);
    wprintf(L"IA32_EFER: %016x\n", regs->ia32_efer);
    wprintf(L"IA32_FEATURE_CONTROL: %016x\n", rdmsr(0x3a));
}

char vmxon_region[4096] __attribute__ ((aligned (4096)));
char vmcs[4096] __attribute__ ((aligned (4096)));
char host_stack[4096] __attribute__ ((aligned (4096)));
char guest_stack[4096] __attribute__ ((aligned (4096)));
char tss[4096] __attribute__ ((aligned (4096)));


EFI_STATUS
EFIAPI
EfiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *_SystemTable
    )
{
    uint32_t error;
    struct registers regs;

    SystemTable = _SystemTable;
    wprintf(L"Starting VMXbench ...\r\n");

    // check the presence of VMX support
    uint32_t ecx;
    asm volatile ("cpuid" : "=c" (ecx) : "a" (1) : "ebx", "edx");
    if ((ecx & 0x20) == 0) // CPUID.1:ECX.VMX[bit 5] != 1
	goto error_vmx_not_supported;
    wprintf(L"VMX is supported\r\n");

    // enable VMX 
    wprintf(L"Enable VMX\r\n");
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 |= 0x2000; // CR4.VME[bit 13] = 1
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));

    // enable VMX operation
    wprintf(L"Enable VMX operation\r\n");
    regs.ia32_feature_control = rdmsr(0x3a);
    if ((regs.ia32_feature_control & 0x1) == 0) {
	regs.ia32_feature_control |= 0x5; // firmware should set this
	wrmsr(0x3a, regs.ia32_feature_control);
    } else if ((regs.ia32_feature_control & 0x4) == 0)
	goto error_vmx_disabled;
    
    // apply fixed bits to CR0 & CR4
    uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1)
    {
	reg |= rdmsr(fixed0);
	reg &= rdmsr(fixed1);
	return reg;
    }
    asm volatile ("mov %%cr0, %0" : "=r" (regs.cr0));
    regs.cr0 = apply_fixed_bits(regs.cr0, 0x486, 0x487);
    asm volatile ("mov %0, %%cr0" :: "r" (regs.cr0));
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));

    // enter VMX operation
    wprintf(L"Enter VMX operation\r\n");
    uint32_t revision_id = rdmsr(0x480);
    uint32_t *ptr = (uint32_t *)vmxon_region;
    ptr[0] = revision_id;
    asm volatile ("vmxon %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmxon;

    // initialize VMCS
    wprintf(L"Initialize VMCS\r\n");
    __builtin_memset(vmcs, 0, 4096);
    ptr = (uint32_t *)vmcs;
    ptr[0] = revision_id;
    asm volatile ("vmclear %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmclear;
    asm volatile ("vmptrld %1" : "=@ccbe" (error) : "m" (ptr));
    if (error)
	goto error_vmptrld;

    // initialize control fields
    uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index)
    {
	uint64_t msr_value = rdmsr(msr_index);
	value |= (msr_value & 0xffffffff);
	value &= (msr_value >> 32);
	return value;
    }
    uint32_t pinbased_ctls = apply_allowed_settings(0x1e, 0x481);
    vmwrite(0x4000, pinbased_ctls);  // Pin-based VM-execution controls
    uint32_t procbased_ctls = apply_allowed_settings(0x0401e9f2, 0x482);
    vmwrite(0x4002, procbased_ctls); // Primary processor-based VM-execution controls
    vmwrite(0x4004, 0x0);            // Exception bitmap
    uint32_t exit_ctls = apply_allowed_settings(0x336fff, 0x483);
    vmwrite(0x400c, exit_ctls);      // VM-exit controls
    uint32_t entry_ctls = apply_allowed_settings(0x93ff, 0x484);
    vmwrite(0x4012, entry_ctls);     // VM-entry controls

    void vmwrite_gh(uint32_t guest_id, uint32_t host_id, uint64_t value)
    {
	vmwrite(guest_id, value);
	vmwrite(host_id, value);
    }
    
    // 16-Bit Guest and Host State Fields
    asm volatile ("mov %%es, %0" : "=m" (regs.es));
    asm volatile ("mov %%cs, %0" : "=m" (regs.cs));
    asm volatile ("mov %%ss, %0" : "=m" (regs.ss));
    asm volatile ("mov %%ds, %0" : "=m" (regs.ds));
    asm volatile ("mov %%fs, %0" : "=m" (regs.fs));
    asm volatile ("mov %%gs, %0" : "=m" (regs.gs));
    asm volatile ("sldt %0" : "=m" (regs.ldt));
    asm volatile ("str %0" : "=m" (regs.tr));
    vmwrite_gh(0x0800, 0x0c00, regs.es); // ES selector
    vmwrite_gh(0x0802, 0x0c02, regs.cs); // CS selector
    vmwrite_gh(0x0804, 0x0c04, regs.ss); // SS selector
    vmwrite_gh(0x0806, 0x0c06, regs.ds); // DS selector
    vmwrite_gh(0x0808, 0x0c08, regs.fs); // FS selector
    vmwrite_gh(0x080a, 0x0c0a, regs.gs); // GS selector
    vmwrite(0x080c, regs.ldt);           // Guest LDTR selector
    vmwrite_gh(0x080e, 0x0c0c, regs.tr); // TR selector
    vmwrite(0x0c0c, 0x08); // dummy TR selector for real hardware

    // 64-Bit Guest and Host State Fields
    vmwrite(0x2800, ~0ULL); // VMCS link pointer
    // vmwrite(0x2802, 0);  // Guest IA32_DEBUGCTL
    regs.ia32_efer = rdmsr(0xC0000080);
    vmwrite_gh(0x2806, 0x2c02, regs.ia32_efer); // IA32_EFER

    // 32-Bit Guest and Host State Fields
    asm volatile ("sgdt %0" : "=m" (regs.gdt));
    asm volatile ("sidt %0" : "=m" (regs.idt));
    uint32_t get_seg_limit(uint32_t selector)
    {
	uint32_t limit;
        asm volatile ("lsl %1, %0" : "=r" (limit) : "r" (selector));
	return limit;
    }
    vmwrite(0x4800, get_seg_limit(regs.es)); // Guest ES limit
    vmwrite(0x4802, get_seg_limit(regs.cs)); // Guest CS limit
    vmwrite(0x4804, get_seg_limit(regs.ss)); // Guest SS limit
    vmwrite(0x4806, get_seg_limit(regs.ds)); // Guest DS limit
    vmwrite(0x4808, get_seg_limit(regs.fs)); // Guest FS limit
    vmwrite(0x480a, get_seg_limit(regs.gs)); // Guest GS limit
    vmwrite(0x480c, get_seg_limit(regs.ldt)); // Guest LDTR limit
    uint32_t tr_limit = get_seg_limit(regs.tr);
    if (tr_limit == 0) tr_limit = 0x0000ffff;
    vmwrite(0x480e, tr_limit);       // Guest TR limit
    vmwrite(0x4810, regs.gdt.limit); // Guest GDTR limit
    vmwrite(0x4812, regs.idt.limit); // Guest IDTR limit
    uint32_t get_seg_access_rights(uint32_t selector)
    {
	uint32_t access_rights;
	asm volatile ("lar %1, %0" : "=r" (access_rights) : "r" (selector));
	return access_rights >> 8;
    }
    vmwrite(0x4814, get_seg_access_rights(regs.es)); // Guest ES access rights
    vmwrite(0x4816, get_seg_access_rights(regs.cs)); // Guest CS access rights
    vmwrite(0x4818, get_seg_access_rights(regs.ss)); // Guest SS access rights
    vmwrite(0x481a, get_seg_access_rights(regs.ds)); // Guest DS access rights
    vmwrite(0x481c, get_seg_access_rights(regs.fs)); // Guest FS access rights
    vmwrite(0x481e, get_seg_access_rights(regs.gs)); // Guest GS access rights
    uint32_t ldtr_access_rights = get_seg_access_rights(regs.ldt);
    if (ldtr_access_rights == 0) ldtr_access_rights = 0x18082;
    vmwrite(0x4820, ldtr_access_rights); // Guest LDTR access rights
    uint32_t tr_access_rights = get_seg_access_rights(regs.tr);
    if (tr_access_rights == 0) tr_access_rights = 0x0808b;
    vmwrite(0x4822, tr_access_rights); // Guest TR access rights

    // Natual-Width Control Fields
    asm volatile ("mov %%cr3, %0" : "=r" (regs.cr3));
    vmwrite_gh(0x6800, 0x6c00, regs.cr0);
    vmwrite_gh(0x6802, 0x6c02, regs.cr3);
    vmwrite_gh(0x6804, 0x6c04, regs.cr4);
    
    uint64_t get_seg_base(uint32_t selector) { return 0; }
    vmwrite(0x6806, get_seg_base(regs.es)); // es base
    vmwrite(0x6808, get_seg_base(regs.cs)); // cs base
    vmwrite(0x680a, get_seg_base(regs.ss)); // ss base
    vmwrite(0x680c, get_seg_base(regs.ds)); // ds base
    vmwrite(0x680e, get_seg_base(regs.fs)); // fs base
    vmwrite(0x6810, get_seg_base(regs.gs)); // gs base
    vmwrite(0x6812, get_seg_base(regs.ldt)); // LDTR base
    vmwrite(0x6814, (uint64_t)tss); // TR base

    vmwrite_gh(0x6816, 0x6C0C, regs.gdt.base); // GDTR base
    vmwrite_gh(0x6818, 0x6C0E, regs.idt.base); // IDT base

    vmwrite(0x6C14, (uint64_t)&host_stack[sizeof(host_stack)]); // HOST_RSP
    vmwrite(0x6C16, (uint64_t)__host_entry); // Host RIP
    vmwrite(0x681C, (uint64_t)&guest_stack[sizeof(guest_stack)]); // GUEST_RSP
    vmwrite(0x681E, (uint64_t)guest_entry); // Guest RIP
    asm volatile ("pushf; pop %%rax" : "=a" (regs.rflags));
    regs.rflags &= ~0x200ULL; // clear interrupt enable flag
    vmwrite(0x6820, regs.rflags);

    if (!__builtin_setjmp(env)) {
	wprintf(L"Launch a VM\r\n");
	asm volatile ("cli");
	asm volatile ("vmlaunch" ::: "memory");
	goto error_vmx;
    } else
	goto disable_vmx;

error_vmx:
    wprintf(L"VMLAUNCH failed: ");
    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
    goto disable_vmx;

error_vmptrld:
    wprintf(L"VMPTRLD failed.\r\n");
    goto disable_vmx;

error_vmclear:
    wprintf(L"VMCLEAR failed.\r\n");
    goto disable_vmx;

error_vmxon:
    wprintf(L"VMXON failed.\r\n");
    goto disable_vmx;

disable_vmx:
    asm volatile ("vmxoff");
    asm volatile ("mov %%cr4, %0" : "=r" (regs.cr4));
    regs.cr4 &= ~0x2000; // CR4.VME[bit 13] = 0
    asm volatile ("mov %0, %%cr4" :: "r" (regs.cr4));
    goto exit;

error_vmx_disabled:
    putws(L"VMX is disabled by the firmware\r\n");
    goto exit;

error_vmx_not_supported:
    putws(L"VMX is not supported in this processor\r\n");
    goto exit;

exit:
    putws(L"Press any key to go back to the UEFI menu\r\n");
    getwchar();
    return EFI_SUCCESS;
}
