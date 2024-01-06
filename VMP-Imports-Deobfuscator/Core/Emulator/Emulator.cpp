#include "Emulator.h"

// @note: @colby57: Check if the API at the given address is valid.
bool Emulator::IsApiValid(std::unordered_map<std::uintptr_t, ApiInfo*>::iterator& ApiInfoIterator, std::uintptr_t Address)
{
	auto it = std::find_if(ApiReader::apiList.begin(), ApiReader::apiList.end(), [Address](const auto& Entry)
	{
		return Entry.first == Address && std::strlen(Entry.second->name) > 0;
	});

	if (it != ApiReader::apiList.end())
	{
		ApiInfoIterator = it;
		return true;
	}

	return false;
}

// @note: @colby57: Check if the given opcode represents a 'RET' instruction.
const bool Emulator::IsInstructionRet(const std::uint8_t Opcode)
{
	return Opcode == 0xc3;
}

const bool Emulator::IsInstructionRetn(const std::uint8_t Opcode[])
{
	// @note: @colby57: Check if the opcode is for a 'RET + 0xOffset' instruction with the correct size.
	return Opcode[0] == 0xC2 && Opcode[1] == sizeof(std::uintptr_t);
}

// @note: @colby57: Get the index of the register involved in the 'MOV' instruction.
int Emulator::GetMovRegIndex(std::uintptr_t& RegisterIndexBuffer)
{
	// @note: @colby57: Iterate through the register table to find a non-excluded register.
	for (int i = 0; i < _countof(eReg64Table); i++)
	{
		if (i != 4)
		{
			if ((uc_reg_read(Unicorn, eReg64Table[i], &RegisterIndexBuffer) == UC_ERR_OK)
				&& RegisterIndexBuffer != 0 && RegisterIndexBuffer != -1)
				return i;
		}
	}

	return -1;
}

const int Emulator::GetPushPopRegIndex()
{
	std::uintptr_t RegisterIndexBuffer;

	// @note: @colby57: Iterate through the register table to find a non-excluded register.
	for (int i = 0; i < _countof(eReg64Table); i++)
	{
		if (i != 4)
		{
			if ((uc_reg_read(Unicorn, eReg64Table[i], &RegisterIndexBuffer) == UC_ERR_OK)
				&& RegisterIndexBuffer != 0)
				return i;
		}
	}

	return -1;
}

// @note: @colby57: Check if the current emulation status is valid.
bool Emulator::CheckCurrentEmulateStatus(std::uint64_t Address)
{
	// @note: @colby57: Increment the emulator counter for each executed instruction.
	EmulatorNum++;

	// @note: @colby57: Check for a timeout condition.
	if (EmulatorNum > ExecuteInstructionMax)
	{
		spdlog::warn("Time out for 0x{:x}. Most likely, an invalid call.", VMPCore::pCurrentPatternAddress);
		return false;
	}

	// @note: @colby57: Check if the instruction pointer is within the valid range.
	if (Address < VMPCore::pImageLoadAddress || Address >(VMPCore::pImageLoadAddress + VMPCore::k32ImageSize))
	{
		spdlog::warn("Instruction pointer [Out Of Range]! Start address: 0x{:x}", VMPCore::pCurrentPatternAddress);
		return false;
	}

	return true;
}

// @note: @colby57: Trace callback function invoked by Unicorn emulator during code execution.
static void Emulator::TraceCallback(uc_engine* Unicorn, uint64_t Address, uint32_t Size, void* UserData)
{
	int Index{};

	std::uint8_t InstructionBuffer[15]{};
	std::uintptr_t RspValue{}; 
	std::uintptr_t Rsp0{};
	std::uintptr_t Rsp4{};
	std::uintptr_t MovRegValue{};

	std::string sApiName{};
	std::unordered_map<DWORD_PTR, ApiInfo*>::iterator ApiInfoIterator{};

	VMPCore::S_IatPatchInfo sIatPatchInfo{};
	sIatPatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_UNKNOWN;

	// @note: @colby57: Check the current emulation status.
	if (!CheckCurrentEmulateStatus(Address))
	{
		uc_emu_stop(Unicorn);
		return;
	}

	// @note: @colby57: Read the instruction at the current address.
	if (uc_mem_read(Unicorn, Address, InstructionBuffer, Size) != UC_ERR_OK)
	{
		spdlog::error("Failed to read address\n");
		uc_emu_stop(Unicorn);
		return;
	}

	if (uc_reg_read(Unicorn, UC_X86_REG_RSP, &RspValue) != UC_ERR_OK)
	{
		spdlog::error("Failed to read Rsp address\n");
		uc_emu_stop(Unicorn);
		return;
	}

	if (uc_mem_read(Unicorn, RspValue, &Rsp0, sizeof(std::uintptr_t)) != UC_ERR_OK)
	{
		spdlog::error("Failed to read Rsp content\n");
		uc_emu_stop(Unicorn);
		return;
	}

	if (IsInstructionRet(InstructionBuffer[0]))
	{
		// @note: @colby57: Check for the specific conditions for MOV REG instruction.
		if (Rsp0 == VMPCore::pCurrentPatternAddress + 5 || Rsp0 == VMPCore::pCurrentPatternAddress + 6)
		{
			Index = GetMovRegIndex(MovRegValue);

			if (MovRegValue == 0)
				return;

			if (IsApiValid(ApiInfoIterator, MovRegValue))
			{
				sApiName = (*ApiInfoIterator).second->name;

				// @note: @colby57: Update IAT patch information for MOV REG instruction.
				sIatPatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_MOV_REG;
				sIatPatchInfo.m_pPatchAddress = (Rsp0 == VMPCore::pCurrentPatternAddress + 5) ?
					VMPCore::pCurrentPatternAddress - (Index == 0 ? 0 : 1) :
					VMPCore::pCurrentPatternAddress;
				sIatPatchInfo.m_iRegIndex = Index;
				sIatPatchInfo.m_pApiAddress = MovRegValue;
				sIatPatchInfo.m_pBaseModule = (*ApiInfoIterator).second->module->modBaseAddr;

				if (Rsp0 == VMPCore::pCurrentPatternAddress + 5)
					sIatPatchInfo.m_iIatEncryptMode = VMPCore::IAT_ENCRYPT_PUSH_CALL;
				else if (Rsp0 == VMPCore::pCurrentPatternAddress + 6)
					sIatPatchInfo.m_iIatEncryptMode = VMPCore::IAT_ENCRYPT_CALL_RET;

				spdlog::info("Call detected: 0x{0:x} - {1}", VMPCore::pCurrentPatternAddress, sApiName);
				uc_emu_stop(Unicorn);
			}
		}
		else
		{
			// @note: @colby57: If Rsp0 is export
			if (IsApiValid(ApiInfoIterator, Rsp0))
			{
				uc_mem_read(Unicorn, RspValue + sizeof(std::uintptr_t), &Rsp4, sizeof(std::uintptr_t));
				sApiName = (*ApiInfoIterator).second->name;

				// @note: @colby57: Update IAT patch information for RET instruction.
				if (Rsp4 == VMPCore::pCurrentPatternAddress + 5) {
					sIatPatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_COMMON;
					sIatPatchInfo.m_iIatEncryptMode = VMPCore::IAT_ENCRYPT_PUSH_CALL;
					sIatPatchInfo.m_pPatchAddress = VMPCore::pCurrentPatternAddress - 1;
					sIatPatchInfo.m_pApiAddress = Rsp0;
					sIatPatchInfo.m_pBaseModule = (*ApiInfoIterator).second->module->modBaseAddr;
				}
				else if (Rsp4 == VMPCore::pCurrentPatternAddress + 6) {
					sIatPatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_COMMON;
					sIatPatchInfo.m_iIatEncryptMode = VMPCore::IAT_ENCRYPT_CALL_RET;
					sIatPatchInfo.m_pPatchAddress = VMPCore::pCurrentPatternAddress;
					sIatPatchInfo.m_pApiAddress = Rsp0;
					sIatPatchInfo.m_pBaseModule = (*ApiInfoIterator).second->module->modBaseAddr;
				}

				spdlog::info("Call detected: 0x{0:x} - {1}", VMPCore::pCurrentPatternAddress, sApiName);
				uc_emu_stop(Unicorn);
			}
		}
	}
	// @note: @colby57: Check for the specific conditions for RET+0xOffset instruction.
	else if (IsInstructionRetn(InstructionBuffer))
	{
		if (IsApiValid(ApiInfoIterator, Rsp0))
		{
			Index = GetPushPopRegIndex();
			sApiName = (*ApiInfoIterator).second->name;
			sIatPatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_JMP;

			// @note: @colby57: Update IAT patch information for RETN instruction.
			sIatPatchInfo.m_iIatEncryptMode = (Index != -1) ? VMPCore::IAT_ENCRYPT_PUSH_CALL : VMPCore::IAT_ENCRYPT_CALL_RET;
			sIatPatchInfo.m_pPatchAddress = (Index != -1) ? VMPCore::pCurrentPatternAddress - 1 : VMPCore::pCurrentPatternAddress;
			sIatPatchInfo.m_pApiAddress = Rsp0;
			sIatPatchInfo.m_pBaseModule = (*ApiInfoIterator).second->module->modBaseAddr;

			spdlog::info("Call detected: 0x{0:x} - {1}", VMPCore::pCurrentPatternAddress, sApiName);
			uc_emu_stop(Unicorn);
		}
	}

	// @note: @colby57: If the IAT patch mode is known, update the patch information.
	if (sIatPatchInfo.m_iCallIatMode != VMPCore::CALL_IAT_UNKNOWN)
	{
		strncpy(sIatPatchInfo.m_szApi, (*ApiInfoIterator).second->name, strlen((*ApiInfoIterator).second->name));
		VMPCore::vecPatchInfo.push_back(sIatPatchInfo);
	}
}

bool Emulator::Init(void* PeBuffer)
{
	if (uc_open(UC_ARCH_X86, UC_MODE_64, &Unicorn))
	{
		spdlog::error("Failed on uc_open()\n");
		return false;
	}

	// @note: @colby57: Map memory for the loaded image.
	if (uc_mem_map(Unicorn, VMPCore::pImageLoadAddress, VMPCore::k32ImageSize + 0x1000, UC_PROT_ALL))
	{
		spdlog::error("[1] Failed to mapping memory!\n");
		return false;
	}

	spdlog::info("Mapped memory range (0x{0:x} - 0x{1:x})", VMPCore::pImageLoadAddress,
		VMPCore::pImageLoadAddress + VMPCore::k32ImageSize + 0x1000);

	// @note: @colby57: Write the loaded PE buffer to the mapped memory.
	if (uc_mem_write(Unicorn, VMPCore::pImageLoadAddress, PeBuffer, VMPCore::k32ImageSize))
	{
		spdlog::error("Failed to write emulation code to memory\n");
		return false;
	}

	// @note: @colby57: Allocate and initialize the stack memory.
	spdlog::info("Stack memory range (0x{0:x} - 0x{1:x})", StackAddress, StackAddress + StackSize);
	StackBuffer = malloc(StackSize);

	if (StackBuffer == NULL)
	{
		spdlog::error("Failed to alloc stack space quit!\n");
		return false;
	}

	if (uc_mem_map(Unicorn, StackAddress, StackSize, UC_PROT_ALL))
	{
		spdlog::error("[2] Failed to mapping memory!\n");
		return false;
	}

	memset(StackBuffer, StackInitValue, StackSize);

	if (uc_mem_write(Unicorn, StackAddress, StackBuffer, StackSize))
	{
		spdlog::error("Failed to write stack data to memory\n");
		return false;
	}

	// @note: @colby57: Initialize and set the initial values for CPU registers.
	std::unordered_map<uc_x86_reg, std::uintptr_t> unMapRegisters =
	{
		{UC_X86_REG_RSP, StackAddress + StackSize - sizeof(std::uintptr_t) * 100},
		{UC_X86_REG_RAX, 0x0},
		{UC_X86_REG_RBX, 0x0},
		{UC_X86_REG_RCX, 0x0},
		{UC_X86_REG_RDX, 0x0},
		{UC_X86_REG_RBP, 0x0},
		{UC_X86_REG_RSI, 0x0},
		{UC_X86_REG_RDI, 0x0},
		{UC_X86_REG_R8, 0x0},
		{UC_X86_REG_R9, 0x0},
		{UC_X86_REG_R10, 0x0},
		{UC_X86_REG_R11, 0x0},
		{UC_X86_REG_R12, 0x0},
		{UC_X86_REG_R13, 0x0},
		{UC_X86_REG_R14, 0x0},
		{UC_X86_REG_R15, 0x0},
	};

	for (const auto& [Register, InitialValue] : unMapRegisters)
	{
		if (uc_reg_write(Unicorn, Register, (void*)&InitialValue) != UC_ERR_OK)
		{
			spdlog::error("Failed to initialize register {}\n", Register);
			return false;
		}
	}

	// @note: @colby57: Allocate and initialize Unicorn context.
	if (uc_context_alloc(Unicorn, &UnicornContext))
	{
		spdlog::error("Failed on uc_context_alloc(\n");
		return false;
	}

	// @note: @colby57: Save the initial context as a snapshot.
	if (uc_context_save(Unicorn, UnicornContext))
	{
		spdlog::error("Failed on uc_context_save()\n");
		return false;
	}

	// @note: @colby57: Add a hook to trace code execution.
	if (uc_hook_add(Unicorn, &UnicornHookTrace, UC_HOOK_CODE, TraceCallback, NULL, 1, 0) != UC_ERR_OK)
	{
		spdlog::error("Failed on uc_hook_add()\n");
		return 0;
	}

	return true;
}

void Emulator::Start(std::uintptr_t Address)
{
	// @note: @colby57: Reset the emulator instruction counter.
	EmulatorNum = 0;

	// @note: @colby57: Restore the saved Unicorn context.
	if (uc_context_restore(Unicorn, UnicornContext))
	{
		spdlog::error("Failed on uc_context_restore()\n");
		return;
	}

	// @note: @colby57: Write the stack data back to memory.
	if (uc_mem_write(Unicorn, StackAddress, StackBuffer, StackSize))
	{
		spdlog::error("Failed to write stack data to memory\n");
		return;
	}

	uc_emu_start(Unicorn, Address, VMPCore::pImageLoadAddress + VMPCore::k32ImageSize - 1, 0, 0);
}
