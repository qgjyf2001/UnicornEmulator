#pragma once
#include "unicorn_emulator.h"
inline int code_count = -1;
#define EXPAND_BY_REG(MACRO)\
	MACRO(UC_X86_REG_EAX, Eax);\
	MACRO(UC_X86_REG_EBX, Ebx);\
	MACRO(UC_X86_REG_ECX, Ecx);\
	MACRO(UC_X86_REG_EDX, Edx);\
	MACRO(UC_X86_REG_ESI, Esi);\
	MACRO(UC_X86_REG_EDI, Edi);\
	MACRO(UC_X86_REG_ESP, Esp);\
	MACRO(UC_X86_REG_EBP, Ebp);\
	MACRO(UC_X86_REG_EIP, Eip);\
	MACRO(UC_X86_REG_EFLAGS, EFlags);\
	MACRO(UC_X86_REG_DR0, Dr0);\
	MACRO(UC_X86_REG_DR1, Dr1);\
	MACRO(UC_X86_REG_DR2, Dr2);\
	MACRO(UC_X86_REG_DR3, Dr3);\
	MACRO(UC_X86_REG_DR6, Dr6);\
	MACRO(UC_X86_REG_DR7, Dr7);

void trace(std::string msg) {
	auto fp = fopen("trace.txt", "a");
	fprintf(fp, "%s\n", msg.data());
	fclose(fp);
}
void stacktrace(uc_engine* uc) {
	uint32_t ebp, eip;
	uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
	uc_reg_read(uc, UC_X86_REG_EIP, &eip);
	trace("====== eip " + hex_string(eip));
	uint32_t current_ebp = ebp;
	int frame_count = 0;
	const int max_frames = 10;
	while (current_ebp != 0 && frame_count < max_frames) {
		uint32_t saved_ebp, saved_eip;
		if (uc_mem_read(uc, current_ebp, &saved_ebp, sizeof(saved_ebp)) != UC_ERR_OK) {
			break;
		}
		if (uc_mem_read(uc, current_ebp + 4, &saved_eip, sizeof(saved_eip)) != UC_ERR_OK) {
			break;
		}
		if (saved_ebp == 0) {
			break;
		}
		trace(std::string("frame ") + std::to_string(frame_count) + " " + hex_string(saved_eip));
		current_ebp = saved_ebp;
		frame_count++;
	}
}
class CallBase {
protected:
	UnicornEmulator* emulator;
	uc_engine* uc;
	void* origin_func;
	void stacktrace() {
		::stacktrace(uc);
	}
	std::string uc_2_string(DWORD address) {
		if (address == 0) {
			return "";
		}
		std::string result;
		while (true) {
			result.push_back('?');
			if (uc_mem_read(uc, address++, &result.back(), 1) != UC_ERR_OK) {
				result.pop_back();
				break;
			}
			if (result.back() == char(0) || result.length() == 255) {
				result.pop_back();
				break;
			}
		}
		return result;
	}
public:
	virtual void Init(UnicornEmulator* emulator, DWORD origin_func) {
		this->emulator = emulator;
		this->uc = emulator->mu;
		this->origin_func = (void*)origin_func;
	}
	virtual void Call() = 0;
	virtual ~CallBase() = default;
};

template <typename... Params>
class StdCallBase : public CallBase {
protected:
	DWORD OriginCall(Params ...args) {
		typedef DWORD(__stdcall* OriginFunc)(Params...);
		return ((OriginFunc)origin_func)(args...);
	}
	void Retn(DWORD result) {
		DWORD ret_esp = esp + 4 + sizeof...(Params) * 4;
		uc_reg_write(uc, UC_X86_REG_EAX, &result);
		uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
		uc_reg_write(uc, UC_X86_REG_ESP, &ret_esp);
	}
	DWORD Args(int index) {
		DWORD result;
		uc_mem_read(uc, esp + 4 * (index + 1), &result, 4);
		return result;
	}
	DWORD esp;
	DWORD ret_addr;
public:
	virtual void Init(UnicornEmulator* emulator, DWORD origin_func) {
		CallBase::Init(emulator, origin_func);
		uc_reg_read(uc, UC_X86_REG_ESP, &esp);
		uc_mem_read(uc, esp, &ret_addr, 4);
	}
	virtual void Call() = 0;
	virtual ~StdCallBase() = default;
};
template <typename... Params>
class InteruptBase : public CallBase {
protected:
	DWORD OriginCall(Params ...args) {
		typedef DWORD(__stdcall* OriginFunc)(Params...);
		return ((OriginFunc)origin_func)(args...);
	}
	void Ret(DWORD result) {
		uc_reg_write(uc, UC_X86_REG_EAX, &result);
		uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
	}
	DWORD Args(int index) {
		DWORD result;
		uc_mem_read(uc, arg_ptr + 4 * index, &result, 4);
		return result;
	}
	DWORD arg_ptr;
	DWORD ret_addr;
	virtual const std::pair<std::string, std::string> ImportSymbol() = 0;
public:
	virtual void Init(UnicornEmulator* emulator, DWORD origin_func) {
		const auto [dll, func] = ImportSymbol();
		auto func_addr = (DWORD)(GetProcAddress(LoadLibraryA(dll.c_str()), func.c_str()));
		CallBase::Init(emulator, func_addr);
		uc_reg_read(uc, UC_X86_REG_EIP, &ret_addr);
		ret_addr += 2;
		uc_reg_read(uc, UC_X86_REG_EDX, &arg_ptr);
	}
	virtual void Call() = 0;
	virtual ~InteruptBase() = default;
};

class RtlAllocateHeap : public StdCallBase<DWORD, DWORD, DWORD> {
public:
	void Call() {
		DWORD HeapHandle = Args(0);
		DWORD Flags = Args(1);
		DWORD Size = Args(2);
		DWORD ret = OriginCall(HeapHandle , Flags, Size);
		trace("RtlAllocateHeap result:" + hex_string(ret) + ",ret_addr:" + hex_string(ret_addr) + ",heap handle:" + hex_string(HeapHandle) + ",flags:" + hex_string(Flags) + ",size:" + hex_string(Size) + ",current_heap:" + hex_string((DWORD)GetProcessHeap()));
		auto addr_base = ret & ~(int)0xfff;
		if (emulator->mapped_mem.find(addr_base) == emulator->mapped_mem.end()) {
			uc_mem_map(uc, addr_base, 0x1000, UC_PROT_ALL);
			uc_mem_write(uc, addr_base, (void*)addr_base, 0x1000);
			emulator->mapped_mem[addr_base] = addr_base + 0x1000;
		}
		Retn(ret);
	}
};
class HookHeapFree : public StdCallBase<DWORD, DWORD, DWORD> {
	void Call() {
		DWORD hHeap = Args(0);
		DWORD dwFlags = Args(1);
		DWORD lpMem = Args(2);
		DWORD ret = OriginCall(hHeap, dwFlags, lpMem);
		trace("HookHeapFree result:" + hex_string(ret) + ",ret_addr:" + hex_string(ret_addr) + ",heap handle:" + hex_string(hHeap) + ",flags:" + hex_string(dwFlags) + ",lpMem:" + hex_string(lpMem));
		Retn(ret);
	}
};
class HookGetCurrentProcessId : public StdCallBase<> {
public:
	void Call() {
		trace("hit GetCurrentProcessId");
		Retn(OriginCall());
	}
};
class HookWaitForSingleObject : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD handle = Args(0);
		DWORD seconds = Args(1);
		trace("WaitForSingleObject:" + hex_string(handle) + ",ret_addr:" + hex_string(ret_addr) + ",seconds:" + hex_string(seconds));
		Retn(0);
	}
};

class HookGetCurrentThread : public StdCallBase<> {
public:
	void Call() {
		auto result = OriginCall();
		trace("hit GetCurrentThread handle:" + hex_string(result));
		Retn(result);
	}
};

class HookGetThreadContext : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD handle = Args(0);
		DWORD lpContext = Args(1);
		if (handle == (DWORD)GetCurrentThread()) {
			char buf[1024] = { 0 };
			auto context = (LPCONTEXT)lpContext;
#define COPY_UC_TO_EXPCETION(UC_REG, REG)\
	uc_reg_read(uc, UC_REG, &context->REG);
			EXPAND_BY_REG(COPY_UC_TO_EXPCETION);
#undef COPY_UC_TO_EXPCETION
			uc_mem_write(uc, lpContext, context, sizeof(CONTEXT));
			sprintf(buf, "hit GetThreadContext lpContext:%x eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x esp:%x ebp:%x eip:%x eflags:%x dr0:%x dr1:%x dr2:%x dr3:%x, dr6:%x dr7:%x", lpContext,
				context->Eax, context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Esp, context->Ebp, context->Eip,
				context->EFlags, context->Dr0, context->Dr1, context->Dr2,context->Dr3,context->Dr6, context->Dr7);
			trace(buf);
			Retn(1);
			return;
		}
		else {
			DWORD result = OriginCall(handle, lpContext);
			emulator->Exception("hit GetThreadContext handle:" + hex_string(handle));
			Retn(result);
		}
	}
};

class HookSetThreadContext : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD handle = Args(0);
		CONTEXT_DEBUG_REGISTERS;
		DWORD lpContext = Args(1);
		auto context = (LPCONTEXT)lpContext;
		if (handle == (DWORD)GetCurrentThread() && context->ContextFlags == 0x10010) {
			char buf[1024] = {0};
			sprintf(buf, "hit SetThreadContext lpContext:%x context_flags:%x eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x esp:%x ebp:%x eip:%x eflags:%x dr0:%x dr1:%x dr2:%x dr3:%x, dr6:%x dr7:%x", lpContext,
				context->ContextFlags ,context->Eax, context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Esp, context->Ebp, context->Eip,
				context->EFlags, context->Dr0, context->Dr1, context->Dr2, context->Dr3, context->Dr6, context->Dr7);
			trace(buf);
			uc_reg_write(uc, UC_X86_REG_DR0, &context->Dr0);
			uc_reg_write(uc, UC_X86_REG_DR1, &context->Dr1);
			uc_reg_write(uc, UC_X86_REG_DR2, &context->Dr2);
			uc_reg_write(uc, UC_X86_REG_DR3, &context->Dr3);
			uc_reg_write(uc, UC_X86_REG_DR6, &context->Dr6);
			uc_reg_write(uc, UC_X86_REG_DR7, &context->Dr7);
			Retn(1);
		}
		else {
			DWORD result = OriginCall(handle, lpContext);
			emulator->Exception("hit SetThreadContext handle:" + hex_string(handle));
			Retn(result);
		}
	}
};

class RtlDispatchException {
private:
	RtlDispatchException() = default;
	DWORD exception_handler = -1;
public:
	static RtlDispatchException& Instance() {
		static RtlDispatchException instance;
		return instance;
	}
	void Call(uc_engine* uc) {
		CONTEXT context;
#define COPY_UC_TO_EXPCETION(UC_REG, REG)\
	uc_reg_read(uc, UC_REG, &context.REG);
		EXPAND_BY_REG(COPY_UC_TO_EXPCETION);
#undef COPY_UC_TO_EXPCETION

		context.Dr6 = 0b11111111111111110000111111110000;
		if (context.Eip == context.Dr0) {
			context.Dr6 |= 1;
		}
		else if (context.Eip == context.Dr1) {
			context.Dr6 |= 2;
		}
		else if (context.Eip == context.Dr2) {
			context.Dr6 |= 4;
		}
		else if (context.Eip == context.Dr3) {
			context.Dr6 |= 8;
		}
		uc_reg_write(uc, UC_X86_REG_DR6, &context.Dr6);
		
		// ¼Ù×°ÉêÇë0x100µÄ¶ÑÕ»¿Õ¼ä
		int32_t esp = context.Esp - 0x100;
		uc_reg_write(uc, UC_X86_REG_ESP, &esp);

		EXCEPTION_POINTERS exception_pointers = { 0 };
		EXCEPTION_RECORD exception_record = { 0 };
		exception_pointers.ContextRecord = (PCONTEXT)kExceptionContextAddr;
		exception_pointers.ExceptionRecord = (PEXCEPTION_RECORD)kExceptionRecordAddr;
		exception_record.ExceptionAddress = (PVOID)context.Eip;
		exception_record.ExceptionCode = EXCEPTION_SINGLE_STEP;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_XSTATE;
		uc_mem_write(uc, kExceptionPointerAddr, &exception_pointers, sizeof(EXCEPTION_POINTERS));
		uc_mem_write(uc, kExceptionRecordAddr, &exception_record, sizeof(EXCEPTION_RECORD));
		uc_mem_write(uc, kExceptionContextAddr, &context, sizeof(CONTEXT));
		int32_t call_stack[2] = { kExceptionCallBackAddr, kExceptionPointerAddr };
		uc_mem_write(uc, esp, call_stack, sizeof(call_stack));
		uc_reg_write(uc, UC_X86_REG_EIP, &exception_handler);

		trace("hit hw breakpoint " + hex_string(context.Eip) + ",handler:" + hex_string(exception_handler)  + ",dr6:" + hex_string(context.Dr6));
		char buf[1024] = { 0 };
		sprintf(buf, "register detauls: context_flags:%x eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x esp:%x ebp:%x eip:%x eflags:%x dr0:%x dr1:%x dr2:%x dr3:%x, dr6:%x dr7:%x",
			context.ContextFlags, context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esi, context.Edi, context.Esp, context.Ebp, context.Eip,
			context.EFlags, context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr6, context.Dr7);
		trace(buf);
	}

	void Callback(uc_engine* uc) {
		int32_t eax;
		uc_reg_read(uc, UC_X86_REG_EAX, &eax);
		CONTEXT context;
		uc_mem_read(uc, kExceptionContextAddr, &context, sizeof(CONTEXT));
#define COPY_EXPCETION_TO_UC(UC_REG, REG)\
	uc_reg_write(uc, UC_REG, &context.REG);
		EXPAND_BY_REG(COPY_EXPCETION_TO_UC);
#undef COPY_EXPCETION_TO_UC
		char buf[1024] = { 0 };
		sprintf(buf, "Exception handle result:%x, register detauls: context_flags:%x eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x esp:%x ebp:%x eip:%x eflags:%x dr0:%x dr1:%x dr2:%x dr3:%x, dr6:%x dr7:%x",
			eax, context.ContextFlags, context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esi, context.Edi, context.Esp, context.Ebp, context.Eip,
			context.EFlags, context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr6, context.Dr7);
		trace(buf); 
	}
	void SetVectoredExceptionHandler(DWORD exception_handler) {
		this->exception_handler = exception_handler;
	}
	void RemoveVectoredExceptionHandler() {
		exception_handler = -1;
	}
};

class RtlAddVectoredExceptionHandler : public StdCallBase<DWORD, DWORD> {
private:
	static LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPtrs) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
public:
	void Call() {
		DWORD First = Args(0);
		DWORD Handler = Args(1);
		auto result = OriginCall(First, (DWORD)&MyUnhandledExceptionFilter);
		trace("hit RtlAddVectoredExceptionHandler handler:" + hex_string(Handler) + ",first:" + hex_string(First) + ",result:" + hex_string(result));
		RtlDispatchException::Instance().SetVectoredExceptionHandler(Handler);
		Retn(result);
	}
};

class NtCreateDebugObject : public InteruptBase<DWORD, DWORD, DWORD, DWORD> {
protected:
	const std::pair<std::string, std::string> ImportSymbol() {
		return { "ntdll.dll", "ZwCreateDebugObject" };
	}
public:
	void Call() {
		DWORD DebugObjectHandle = Args(0);
		DWORD DesiredAccess = Args(1);
		DWORD ObjectAttributes = Args(2);
		DWORD Flags = Args(3);
		auto result = OriginCall(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
		uc_mem_write(uc, DebugObjectHandle, (void*)DebugObjectHandle, sizeof(HANDLE));
		trace("hit NtCreateDebugObject DebugObjectHandle:" + hex_string(DebugObjectHandle) + ",DesiredAccess:" + hex_string(DesiredAccess) +
			",ObjectAttributes:" + hex_string(ObjectAttributes) + ",Flags:" + hex_string(Flags) + ",result:" + hex_string(result));
		Ret(result);
	}
};

class NtQueryInformationProcess : public InteruptBase<DWORD, DWORD, DWORD, DWORD, DWORD> {
protected:
	const std::pair<std::string, std::string> ImportSymbol() {
		return { "ntdll.dll", "ZwQueryInformationProcess" };
	}
public:
	void Call() {
		DWORD ProcessHandle = Args(0);
		DWORD ProcessInformationClass = Args(1);
		DWORD ProcessInformation = Args(2);
		DWORD ProcessInformationLength = Args(3);
		DWORD ReturnLength = Args(4);
		auto result = OriginCall(ProcessHandle, ProcessInformationClass, ProcessInformation,
			ProcessInformationLength, ReturnLength);
		trace("hit NtQueryInformationProcess ProcessHandle:" + hex_string(ProcessHandle) + ",ProcessInformationClass:" + hex_string(ProcessInformationClass) +
			",ProcessInformation:" + hex_string(ProcessInformation) + ",ProcessInformationLength:" + hex_string(ProcessInformationLength)
			+ ",ReturnLength:" + hex_string(ReturnLength));
		uc_mem_write(uc, ProcessInformation, (void*)ProcessInformation, ProcessInformationLength);
		if (!PtrCheck::IsBadWritePtrLocal((void*)ReturnLength)) {
			uc_mem_write(uc, ReturnLength, (void*)ReturnLength, sizeof(ULONG));
		}
		Ret(result);
	}
};

class NtQuerySystemInformation : public InteruptBase<DWORD, DWORD, DWORD, DWORD> {
protected:
	const std::pair<std::string, std::string> ImportSymbol() {
		return { "ntdll.dll", "ZwQuerySystemInformation" };
	}
public:
	void Call() {
		DWORD SystemInformationClass = Args(0);
		DWORD SystemInformation = Args(1);
		DWORD SystemInformationLength = Args(2);
		DWORD ReturnLength = Args(3);
		auto result = OriginCall(SystemInformationClass, SystemInformation, SystemInformationLength,
			ReturnLength);
		trace("hit NtQuerySystemInformation SystemInformationClass:" + hex_string(SystemInformationClass) +
			",SystemInformation:" + hex_string(SystemInformation) + ",SystemInformationLength:" + hex_string(SystemInformationLength)
			+ ",ReturnLength:" + hex_string(ReturnLength));
		uc_mem_write(uc, SystemInformation, (void*)SystemInformation, SystemInformationLength);
		if (!PtrCheck::IsBadWritePtrLocal((void*)ReturnLength)) {
			uc_mem_write(uc, ReturnLength, (void*)ReturnLength, sizeof(ULONG));
		}
		Ret(result);
	}
};

class HookGetProcessHeap : public StdCallBase<> {
public:
	void Call() {
		trace("hit GetProcessHeap");
		Retn(OriginCall());
	}
};

class HookGetComputerNameA : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD lpBuffer = Args(0);
		DWORD nsize = Args(1);
		DWORD result = OriginCall(lpBuffer, nsize);
		uc_mem_write(uc, lpBuffer, (void*)lpBuffer, nsize);
		trace("hit GetComputerNameA " + std::string((char*)lpBuffer, *(DWORD*)nsize));
		Retn(result);
	}
};

class HookRegOpenKeyA : public StdCallBase<DWORD, DWORD, DWORD> {
public:
	void Call() {
		DWORD hKey = Args(0);
		DWORD lpSubKey = Args(1);
		DWORD phkResult = Args(2);
		std::string subkey = uc_2_string(lpSubKey);
		trace("hit RegOpenKeyA, hkey: " + hex_string(hKey) + ",subkey:" + subkey + ",phkResult:" + hex_string(phkResult));
		DWORD result = OriginCall(hKey, (DWORD)subkey.data(), phkResult);
		uc_mem_write(uc, phkResult, (void*)phkResult, sizeof(HKEY));
		Retn(result);
	}
};

class HookRegQueryValueExA : public StdCallBase<DWORD, DWORD, DWORD, DWORD, DWORD, DWORD> {
public:
	void Call() {
		DWORD hKey = Args(0);
		DWORD lpValueName = Args(1);
		DWORD lpReserved = Args(2);
		DWORD lpType = Args(3);
		DWORD lpData = Args(4);
		DWORD lpcbData = Args(5);
		std::string subkey = uc_2_string(lpValueName);
		trace("hit RegQueryValueExA, hkey: " + hex_string(hKey) + ",lpValueName:" + subkey);
		DWORD result = OriginCall(hKey, (DWORD)subkey.data(), lpReserved, lpType, lpData, lpcbData);
		if (!PtrCheck::IsBadWritePtrLocal((void*)lpType)) {
			uc_mem_write(uc, lpType, (void*)lpType, sizeof(DWORD));
		}
		if (!PtrCheck::IsBadWritePtrLocal((void*)lpcbData)) {
			uc_mem_write(uc, lpcbData, (void*)lpcbData, sizeof(DWORD));
			if (!PtrCheck::IsBadWritePtrLocal((void*)lpData)) {
				uc_mem_write(uc, lpData, (void*)lpData, *(DWORD*)lpData);
				trace("RegQueryValueExA result: " + std::string((char*)lpData));
			}
		}
		Retn(result);
	}
};

class HookGetModuleHandleA : public StdCallBase<DWORD> {
public:
	void Call() {
		DWORD lpModuleName = Args(0);
		std::string module_name = uc_2_string(lpModuleName);
		trace("hit GetModuleHandleA,module_name:" + module_name);
		DWORD result = OriginCall((DWORD)module_name.data());
		Retn(result);
	}
};
extern std::unordered_map<std::string, std::pair<std::string, int>> winapi_invert_map;
class HookGetProcAddress : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD hModule = Args(0);
		DWORD lpProcName = Args(1);
		std::string proc_name = uc_2_string(lpProcName);
		trace("hit GetProcAddress,proc_name:" + proc_name);
		if (auto iter = winapi_invert_map.find(proc_name); iter != winapi_invert_map.end()) {
			Retn(iter->second.second);
		}
		else {
			emulator->Exception("GetProcAddress error ,proc_name:" + proc_name);
			Retn(0);
		}
	}
};

class HookGetNativeSystemInfo : public StdCallBase<DWORD> {
public:
	void Call() {
		DWORD lpSystemInfo = Args(0);
		trace("hit GetNativeSystemInfo");
		auto result = OriginCall(lpSystemInfo);
		uc_mem_write(uc, lpSystemInfo, (void*)lpSystemInfo, sizeof(SYSTEM_INFO));
		Retn(result);
	}
};

class HookRegCloseKey : public StdCallBase<DWORD> {
public:
	void Call() {
		DWORD hKey = Args(0);
		trace("hit RegCloseKey");
		auto result = OriginCall(hKey);
		Retn(result);
	}
};


class ZwQuerySystemInformation : public StdCallBase<DWORD, DWORD, DWORD, DWORD> {
public:
	void Call() {
		DWORD SystemInformationClass = Args(0);
		DWORD SystemInformation = Args(1);
		DWORD SystemInformationLength = Args(2);
		DWORD ReturnLength = Args(3);
		auto result = OriginCall(SystemInformationClass, SystemInformation, SystemInformationLength,
			ReturnLength);
		trace("hit ZwQuerySystemInformation SystemInformationClass:" + hex_string(SystemInformationClass) +
			",SystemInformation:" + hex_string(SystemInformation) + ",SystemInformationLength:" + hex_string(SystemInformationLength)
			+ ",ReturnLength:" + hex_string(ReturnLength));
		uc_mem_write(uc, SystemInformation, (void*)SystemInformation, SystemInformationLength);
		if (!PtrCheck::IsBadWritePtrLocal((void*)ReturnLength)) {
			uc_mem_write(uc, ReturnLength, (void*)ReturnLength, sizeof(ULONG));
		}
		Retn(result);
	}
};

class HookFindWindowA : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD lpClassName = Args(0);
		DWORD lpWindowName = Args(1);
		std::string class_name = uc_2_string(lpClassName);
		std::string window_name = uc_2_string(lpWindowName);
		trace("hit FindWindowA,class_name:" + class_name + ",window_name:" +window_name);
		DWORD result = OriginCall(lpClassName ? (DWORD)class_name.data() : lpClassName,
			lpWindowName ? (DWORD)window_name.data() : lpWindowName);;
		Retn(result);
	}
};

class HookFindWindowExA : public StdCallBase<DWORD, DWORD, DWORD, DWORD> {
public:
	void Call() {
		DWORD hWndParent = Args(0);
		DWORD hWndChildAfter = Args(1);
		DWORD lpClassName = Args(2);
		DWORD lpWindowName = Args(3);
		std::string class_name = uc_2_string(lpClassName);
		std::string window_name = uc_2_string(lpWindowName);
		trace("hit FindWindowExA,hWndParent:" + hex_string(hWndParent) + ",hWndChildAfter:" + hex_string(hWndChildAfter)
			+ ",class_name:" + class_name + ",window_name:" + window_name);
		DWORD result = OriginCall(hWndParent, hWndChildAfter, lpClassName ? (DWORD)class_name.data() : lpClassName,
			lpWindowName ? (DWORD)window_name.data() : lpWindowName);
		Retn(result);
	}
};

class HookGetWindowThreadProcessId : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD hWnd = Args(0);
		DWORD lpdwProcessId = Args(1);
		trace("hit GetWindowThreadProcessId");
		DWORD result = OriginCall(hWnd, lpdwProcessId);
		if (!PtrCheck::IsBadWritePtrLocal((void*)lpdwProcessId)) {
			uc_mem_write(uc, lpdwProcessId, (void*)lpdwProcessId, sizeof(DWORD));
		}
		Retn(result);
	}
};
#include <winsock2.h>
class HookWSAStartup : public StdCallBase<DWORD, DWORD> {
public:
	void Call() {
		DWORD wVersionRequested = Args(0);
		DWORD lpWSAData = Args(1);
		trace("hit WSAStartup");
		DWORD result = OriginCall(wVersionRequested, lpWSAData);
		if (!PtrCheck::IsBadWritePtrLocal((void*)lpWSAData)) {
			uc_mem_write(uc, lpWSAData, (void*)lpWSAData, sizeof(WSADATA));
		}
		Retn(result);
	}
};

class Hookgethostbyname : public StdCallBase<DWORD> {
public:
	void Call() {
		DWORD name = Args(0);
		std::string name_str = uc_2_string(name);
		trace("hit gethostbyname name:" + name_str);
		Retn(0);
	}
};

class RtlRemoveVectoredExceptionHandler : public StdCallBase<DWORD> {
public:
	void Call() {
		DWORD handle = Args(0);
		code_count = 0;
		auto result = OriginCall(handle);
		trace("hit RtlRemoveVectoredExceptionHandler handle:" + hex_string(handle) + ",result:" + hex_string(result));
		RtlDispatchException::Instance().RemoveVectoredExceptionHandler();
		Retn(result);
	}
};