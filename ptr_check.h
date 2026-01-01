#pragma once
class PtrCheck
{
public:
	static bool IsBadWritePtrLocal(void* p);
	static bool IsBadReadPtrLocal(void* p);
};

