#pragma once
#include <unicorn/unicorn.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
std::string hex_string(uint32_t value);
class UnicornEmulator
{
public:
	static UnicornEmulator& Instance() {
		static UnicornEmulator unicorn_emulator;
		return unicorn_emulator;
	}
	UnicornEmulator();
	~UnicornEmulator();
	void MapFile(uint32_t base_address, const std::string filename, bool skip_map = false);
	void Init(PCONTEXT context);
	void Run(uint32_t start_address, uint32_t end_address);
	void Finalize(PCONTEXT context);

	uc_engine* mu = nullptr;
	std::unordered_map<DWORD, DWORD> mapped_mem;
	static void Exception(const std::string message);
private:
	static void hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void hook_exception(uc_engine* uc, uint32_t intno, void* user_data);
	static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	std::vector<uint8_t> OpenAndReadFile(const std::string& filename);
	uint32_t eip;
	uint32_t start_address;
	uint32_t end_address;
	uint32_t stack_start_address;
	uint32_t stack_end_address;
	std::queue<int32_t> queue;
};

