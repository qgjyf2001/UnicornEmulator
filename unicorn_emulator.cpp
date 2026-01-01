#include <vector>
#include <fstream>
#include <sstream>
#include "ptr_check.h"
#include "unicorn_emulator.h"
#include "winapi_call.h"
std::unordered_map<int, std::pair<const char*, const char*>> winapi_map;
std::unordered_map<std::string, std::pair<std::string, int>> winapi_invert_map;
std::unordered_map<std::string, CallBase*> winapi_udf_map = {
	{"RtlAllocateHeap", new RtlAllocateHeap},
	{"GetCurrentProcessId", new HookGetCurrentProcessId},
	{"HeapFree", new HookHeapFree},
	{"WaitForSingleObject", new HookWaitForSingleObject},
	{"GetCurrentThread", new HookGetCurrentThread},
	{"GetThreadContext", new HookGetThreadContext},
	{"SetThreadContext", new HookSetThreadContext},
	{"RtlAddVectoredExceptionHandler", new RtlAddVectoredExceptionHandler },
	{"RtlRemoveVectoredExceptionHandler", new RtlRemoveVectoredExceptionHandler },
	{"GetProcessHeap", new HookGetProcessHeap},
	{"GetComputerNameA", new HookGetComputerNameA},
	{"RegOpenKeyA", new HookRegOpenKeyA},
	{"RegQueryValueExA", new HookRegQueryValueExA},
	{"GetModuleHandleA", new HookGetModuleHandleA},
	{"GetProcAddress", new HookGetProcAddress},
	{"GetNativeSystemInfo", new HookGetNativeSystemInfo},
	{"RegCloseKey", new HookRegCloseKey},
	{"ZwQuerySystemInformation", new ZwQuerySystemInformation},
	{"FindWindowA", new HookFindWindowA},
	{"FindWindowExA", new HookFindWindowExA},
	{"GetWindowThreadProcessId", new HookGetWindowThreadProcessId},
	{"WSAStartup", new HookWSAStartup},
	{"gethostbyname", new Hookgethostbyname},
};
std::unordered_map<DWORD, CallBase*> nt_udf_map = {
	{0xab, new NtCreateDebugObject},
	{0x19, new NtQueryInformationProcess},
	{0x36, new NtQuerySystemInformation}
};
std::string hex_string(uint32_t value) {
	char buffer[11]; // "0x" + 8 字符 + '\0'
	snprintf(buffer, sizeof(buffer), "0x%08x", value);
	return std::string(buffer);
}



void CPUID(uint32_t eaxInput, uint32_t ecxInput, uint32_t* eaxOut, uint32_t* ebxOut, uint32_t* ecxOut, uint32_t* edxOut)
{
	__asm {
		mov eax, eaxInput
		mov ecx, ecxInput
		cpuid
		mov edi, eaxOut
		mov[edi], eax
		mov edi, ebxOut
		mov[edi], ebx
		mov edi, ecxOut
		mov[edi], ecx
		mov edi, edxOut
		mov[edi], edx
	}
}

DWORD GetFSValue(DWORD offset1) {
	DWORD result = 0;
	__asm {
		mov eax, offset1
		mov eax, fs: [eax]
		mov result, eax
	}

	return result;
}

void SetFsValue(DWORD offset1, DWORD value) {
	__asm {
		mov eax, offset1
		mov edx, value
		mov fs : [eax] , edx
	}
}

std::vector<uint8_t> UnicornEmulator::OpenAndReadFile(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file) {
		Exception("无法打开文件: " + filename);
	}
	return std::vector<uint8_t>(
		(std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>()
		);
}

bool UnicornEmulator::hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	DWORD ip = 0;
	uc_reg_read(uc, UC_X86_REG_EIP, &ip);
	if (type == UC_MEM_READ_UNMAPPED) {
		if (!PtrCheck::IsBadReadPtrLocal((void*)address)) {
			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);
			DWORD pageSize = sysInfo.dwPageSize;
			void* alignedMemPtr = (void*)((uintptr_t)address & ~(pageSize - 1));
			uc_mem_map(uc, (uint32_t)alignedMemPtr, pageSize, UC_PROT_ALL);
			uc_mem_write(uc, (uint32_t)alignedMemPtr, alignedMemPtr, pageSize);
			trace("mem_map read address:" + hex_string((DWORD)alignedMemPtr));
		}
		else {
			Exception("Invalid READ at " + hex_string(address) + ",ip:" + hex_string(ip));
		}
	}
	else if (type == UC_MEM_WRITE_UNMAPPED) {
		if (!PtrCheck::IsBadWritePtrLocal((void*)address)) {
			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);
			DWORD pageSize = sysInfo.dwPageSize;
			void* alignedMemPtr = (void*)((uintptr_t)address & ~(pageSize - 1));
			uc_mem_map(uc, (uint32_t)alignedMemPtr, pageSize, UC_PROT_ALL);
			uc_mem_write(uc, (uint32_t)alignedMemPtr, alignedMemPtr, pageSize);
			trace("mem_map write address:" + hex_string((DWORD)alignedMemPtr));
		}
		else {
			Exception("Invalid WRITE at " + hex_string(address) + ",ip:" + hex_string(ip));
		}
	}
	else if (type == UC_MEM_FETCH_UNMAPPED) {
		trace("code_count:" + std::to_string(code_count));
		stacktrace(uc);
		Exception("Invalid FETCH at " + hex_string(address) + ",ip:" + hex_string(ip));
	}
	else {
		Exception("Unknown memory error at " + hex_string(address) + ",ip:" + hex_string(ip));
	}
	return true;
}


void UnicornEmulator::hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	if (address >= kExceptionPointerAddr && address < kExceptionPointerAddr + 0x1000) {
		trace("hit write exception ptr " + hex_string(address));
		return;
	}
	if (address >= kFsBase && address <= kFsBase + 0x1000) {
		DWORD offset = address - kFsBase;
		if (size == 4) {
			SetFsValue(offset, value);
			trace("write fs:[" + hex_string(offset) + "]=" + hex_string((uint32_t)(((EXCEPTION_REGISTRATION_RECORD*)value)->Handler)));
		}
		else {
			Exception("bad write fs, offset:" + hex_string(offset) + ",value" + hex_string(value) + ",size:" + hex_string(size));
		}
		return;
	}
	if (PtrCheck::IsBadWritePtrLocal((void*)address)) {
		Exception("write bad ptr " + hex_string(address));
	}
	else {
		auto* self = (UnicornEmulator*)user_data;
		if (auto iter = winapi_map.find(value); iter != winapi_map.end()) {
				auto handle = LoadLibraryA(iter->second.second);
				auto func_addr = (DWORD)GetProcAddress(handle, iter->second.first);
				value = func_addr;
		}
		switch (size) {
		case 1:
			*((uint8_t*)address) = (uint8_t)value;
			break;
		case 2:
			*((uint16_t*)address) = (uint16_t)value;
			break;
		case 4:
			*((uint32_t*)address) = (uint32_t)value;
			break;
		case 8:
			*((uint64_t*)address) = (uint64_t)value;
			break;
		default:
			Exception("Unsupported write size:" + std::to_string(size));
			break;
		}
	}
}

void UnicornEmulator::hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	// 读取指令字节
	std::vector<uint8_t> instruction(size);
	uc_mem_read(uc, address, instruction.data(), size);
	if (instruction.size() == 2 && instruction[0] == 0x0F && instruction[1] == 0xA2) {
		uint32_t eax, ecx;
		uc_reg_read(uc, UC_X86_REG_EAX, &eax);
		uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
		uint32_t result_eax, result_ebx, result_ecx, result_edx;
		CPUID(eax, ecx, &result_eax, &result_ebx, &result_ecx, &result_edx);
		uc_reg_write(uc, UC_X86_REG_EAX, &result_eax);
		uc_reg_write(uc, UC_X86_REG_EBX, &result_eax);
		uc_reg_write(uc, UC_X86_REG_ECX, &result_ecx);
		uc_reg_write(uc, UC_X86_REG_EDX, &result_edx);

		uint64_t eip = address + size;
		uc_reg_write(uc, UC_X86_REG_EIP, &eip);
	}
	auto* self = (UnicornEmulator*)user_data;

	if (address >= 0x11c06100 && address <= 0x11c06160) {
		RtlDispatchException::Instance().Call(uc);
	}
	if (address == kExceptionCallBackAddr) {
		RtlDispatchException::Instance().Callback(uc);
	}
	if (code_count >= 0) {
		code_count++;
	}
	if (instruction.size() == 2 && instruction[0] == 0xcd && instruction[1] == 0x2e) {
		uint32_t eax;
		uc_reg_read(uc, UC_X86_REG_EAX, &eax);
		if (auto udf_iter = nt_udf_map.find(eax); udf_iter != nt_udf_map.end()) {
			auto udf = udf_iter->second;
			udf->Init(self, 0);
			udf->Call();
		}
		else {
			trace("hit int 0x2e eax:" + hex_string(eax));
		}
	}
	if (auto iter = winapi_map.find(address); iter != winapi_map.end() && instruction[0] == 0x90) {
		auto handle = LoadLibraryA(iter->second.second);
		auto func_addr = (DWORD)GetProcAddress(handle, iter->second.first);
		if (auto udf_iter = winapi_udf_map.find(iter->second.first);udf_iter != winapi_udf_map.end()) {
			auto udf = udf_iter->second;
			udf->Init(self, func_addr);
			udf->Call();
		}
		else {
			Exception(std::string("find func:") + iter->second.first + ",addr:" + hex_string(func_addr));
			uc_reg_write(uc, UC_X86_REG_EIP, &func_addr);
			uc_emu_stop(uc);
		}
	}
	if (self->start_address <= address && self->end_address >= address) {
		uc_emu_stop(uc);
	}
}

void UnicornEmulator::hook_exception(uc_engine* uc, uint32_t intno, void* user_data) {
	DWORD ip = 0;
	uc_reg_read(uc, UC_X86_REG_EIP, &ip);
	Exception("cpu exception " + hex_string(intno) + ",ip:" + hex_string(ip));
}

UnicornEmulator::UnicornEmulator() {
	if (uc_open(UC_ARCH_X86, UC_MODE_32, &mu) != UC_ERR_OK) {
		Exception("UnicornEmulator:uc_open error");
	}
	uc_hook hh;
	uc_hook_add(mu, &hh, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);
	uc_hook write_hook;
	uc_hook_add(mu, &write_hook, UC_HOOK_MEM_WRITE, (void*)hook_mem_write, nullptr, 1, 0);
	uc_hook invalid_hook;
	uc_hook_add(mu, &invalid_hook, UC_HOOK_MEM_INVALID, (void*)hook_mem_invalid, nullptr, 1, 0);
	uc_hook eh;
	uc_hook_add(mu, &eh, UC_HOOK_INTR, (void*)hook_exception, nullptr, 1, 0);

	uc_mem_map(mu, kFsBase, 0x1000, UC_PROT_ALL);
	constexpr DWORD FS_MSR = 0xC0000100;
	uc_x86_msr msr_value;
	msr_value.rid = FS_MSR;  // MSR 寄存器 ID
	msr_value.value = kFsBase;  // 要设置的值
	uc_reg_write(mu, UC_X86_REG_MSR, &msr_value);

	uc_mem_map(mu, kExceptionPointerAddr, 0x1000, UC_PROT_ALL);
	constexpr char nop_bytes[] = { 0x90 };
	auto err = uc_mem_write(mu, kExceptionCallBackAddr, nop_bytes, 1);

	std::ifstream file("winapi.fmap");
	std::string line;
	std::unordered_map<DWORD, DWORD> winapi_addr_map;
	while (std::getline(file, line)) {
		std::istringstream iss(line);
		int winapi_addr;
		std::string function_name;
		std::string dll_name;
		iss >> winapi_addr;
		iss >> function_name;
		iss >> dll_name;
		char* func_str = strdup(function_name.c_str());
		char* dll_str = strdup(dll_name.c_str());
		winapi_invert_map[func_str] = { dll_str, winapi_addr };
		winapi_map.emplace(winapi_addr,
			std::make_pair(static_cast<const char*>(func_str),
				static_cast<const char*>(dll_str)));
		auto addr_base = winapi_addr & ~(int)0xfff;
		if (winapi_addr_map.find(addr_base) == winapi_addr_map.end()) {
			winapi_addr_map[addr_base] = addr_base + 0x1000;
			auto err = uc_mem_map(mu, addr_base, 0x1000, UC_PROT_ALL);
			if (err != UC_ERR_OK) {
				Exception("map mem error");
			}
		}
		constexpr char nop_bytes[] = { 0x90 };
		auto err = uc_mem_write(mu, winapi_addr, nop_bytes, 1);
		if (err != UC_ERR_OK) {
			Exception("mem write error");
		}
	}
}
void UnicornEmulator::MapFile(uint32_t base_address, std::string filename, bool skip_map) {
	auto mem_data = OpenAndReadFile(filename);
	if (!skip_map) {
		if (uc_mem_map(mu, base_address, mem_data.size(), UC_PROT_ALL) != UC_ERR_OK) {
			Exception("UnicornEmulator:MapFile error " + filename);
		}
	}
	if (uc_mem_write(mu, base_address, mem_data.data(), mem_data.size()) != UC_ERR_OK) {
		Exception("UnicornEmulator:MapFile error " + filename);
	}
}
void UnicornEmulator::Init(PCONTEXT context) {
#define COPY_EXCEPTION_TO_UC(UC_REG, REG)\
	uc_reg_write(mu, UC_REG, &context->REG);
	EXPAND_BY_REG(COPY_EXCEPTION_TO_UC);
#undef COPY_EXCEPTION_TO_UC
	eip = context->Eip;

	// write stack
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	DWORD pageSize = sysInfo.dwPageSize;
	void* alignedStackPtr = (void*)((uintptr_t)context->Esp & ~(pageSize - 1));
	stack_start_address = (uint32_t)alignedStackPtr - pageSize;
	stack_end_address = (uint32_t)alignedStackPtr + 2 * pageSize;
	uc_mem_map(mu, stack_start_address, stack_end_address - stack_start_address, UC_PROT_ALL);
	uc_mem_write(mu, stack_start_address, (void*)stack_start_address, stack_end_address - stack_start_address);
	BYTE fsData[0x1000] = { 0 };
	for (DWORD i = 0; i < 0x1000; i += 4) {
		*(DWORD*)(fsData + i) = GetFSValue(i);
	}
	
	uc_mem_write(mu, kFsBase, fsData, 0x1000);
}

void UnicornEmulator::Finalize(PCONTEXT context) {
#define COPY_UC_TO_EXPCETION(UC_REG, REG)\
	uc_reg_read(mu, UC_REG, &context->REG);\
	if (auto iter = winapi_map.find(context->REG);iter != winapi_map.end()) {\
		auto handle = LoadLibraryA(iter->second.second);\
		auto func_addr = (DWORD)GetProcAddress(handle, iter->second.first);\
		context->REG = func_addr;\
	}
	EXPAND_BY_REG(COPY_UC_TO_EXPCETION);

#undef COPY_UC_TO_EXPCETION
	uc_mem_unmap(mu, stack_start_address, stack_end_address - stack_start_address);
}
void UnicornEmulator::Run(uint32_t start_address, uint32_t end_address) {
	this->start_address = start_address;
	this->end_address = end_address;
	auto err = uc_emu_start(mu, eip, 0, 0, 0);
	// 检查执行结果
	if (err != UC_ERR_OK) {
		DWORD ip_reg = 0;
		uc_reg_read(mu, UC_X86_REG_EIP, &ip_reg);
		Exception(std::string("eip:") + hex_string(eip) +",Execution encountered an exception: " + uc_strerror(err) + 
			std::string(",ip_reg:") + hex_string(ip_reg));
	}
}
UnicornEmulator::~UnicornEmulator() {
	if (mu != nullptr) {
		uc_close(mu);
		mu = nullptr;
	}
}
void UnicornEmulator::Exception(const std::string message) {
	MessageBoxA(nullptr, message.c_str(), "UnicornEmulator", 0);
}
