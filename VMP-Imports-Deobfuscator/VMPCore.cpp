#include <Zydis/Zydis.h>

#include <unicorn/unicorn.h>

#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Patterns/PatternSearch.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/ansicolor_sink.h"

#include "Core/Utils/StringConversion/StringConversion.h"

#include "Dependencies/argparse.hpp"

#include "Core/Emulator/Emulator.h"
#include "Core/Pe/PeParser.h"
#include "Core/ZydisWrapper/Wrapper.h"

#include "VMPCore.h"

using namespace blackbone;
using namespace blackbone::pe;


namespace
{
	std::uintptr_t FindModuleBaseByAddress(std::uintptr_t Address)
	{
		for (const auto& sModule : ProcessAccessHelp::moduleList)
		{
			const auto Base = static_cast<std::uintptr_t>(sModule.modBaseAddr);
			const auto Size = static_cast<std::uintptr_t>(sModule.modBaseSize);

			if (Address >= Base && Address < Base + Size)
				return Base;
		}

		return 0;
	}

	bool ModuleListContains(const std::vector<std::uintptr_t>& Modules, std::uintptr_t ModuleBase)
	{
		return std::find(Modules.begin(), Modules.end(), ModuleBase) != Modules.end();
	}
}
void FilterAddresses(std::uintptr_t pImageBase, std::uint32_t u32ImageSize, void* pPeBuffer, std::vector<std::uintptr_t>& vecPatternAddresses, std::vector<ptr_t>& vecAddressResults, std::uint32_t u32SectionBase, std::uint32_t u32SectionSize)
{
	std::uintptr_t pCalculatedAddress{};
	S_DisasmWrapper sDisasm{};

	// @note: @colby57: Iterate through the vector of address results.
	for (const auto& temp : vecAddressResults)
	{
		std::uintptr_t pResultItem = static_cast<std::uintptr_t>(temp);
		std::uintptr_t pOffset = pResultItem - pImageBase;
		std::uintptr_t pTargetAddress = reinterpret_cast<std::uintptr_t>(pPeBuffer) + pOffset;

		sDisasm.m_pRuntimeAddr = static_cast<std::uintptr_t>(pResultItem);

		// @note: @colby57: Check if the first byte at the target address is a relative call (0xE8) and disassemble the instruction.
		if (*(unsigned char*)pTargetAddress == 0xE8 && ZydisWrapper::Disasm(sDisasm, pTargetAddress, 5))
		{
			// @note: @colby57: Calculate the absolute address using the disassembled instruction.
			if (pCalculatedAddress = ZydisWrapper::CalculateAbsoluteAddr(sDisasm, 0); pCalculatedAddress == NULL)
				continue;

			// @note: @colby57: Skip addresses that are outside the image boundaries.
			if (pCalculatedAddress > (pImageBase + u32ImageSize) || pCalculatedAddress < pImageBase)
				continue;

			// @note: @colby57: Skip addresses within the specified section boundaries.
			if (pCalculatedAddress >= (pImageBase + u32SectionBase) &&
				pCalculatedAddress <= (pImageBase + u32SectionBase + u32SectionSize))
				continue;

			// @note: @colby57: Add the filtered address to the pattern address list.
			vecPatternAddresses.emplace_back(pResultItem);
		}
	}
}

void VMPCore::ParseModules()
{
	std::set<std::uintptr_t> uniqueModuleSet;

	// @note: @colby57: Iterate through the patch information vector using a range-based for loop.
	for (const auto& sIatPatchInfo : vecPatchInfo)
		// @note: @colby57: Check if the module address is not already in the set.
		uniqueModuleSet.insert(sIatPatchInfo.m_pBaseModule);

	// @note: @colby57: Assign the unique module addresses to vecModuleList.
	vecModuleList.assign(uniqueModuleSet.begin(), uniqueModuleSet.end());
	spdlog::info("Module count: {}\n", vecModuleList.size());
}

void VMPCore::GetModulePathByAddress(std::uintptr_t Address, ModuleInfo& sTargetModule)
{
	// @note: @colby57: Iterate through the module list using const reference.
	for (const auto& sModule : ProcessAccessHelp::moduleList)
	{
		// @note: @colby57: Check if the module base address matches the provided address.
		if (sModule.modBaseAddr == Address)
		{
			// @note: @colby57: Assign the module information to the target module.
			sTargetModule = sModule;
			return;
		}
	}
}

void VMPCore::ParseApiList()
{
	// @note: @colby57: Iterate through the module list.
	for (const auto& pImportModule : vecModuleList)
	{
		std::set<std::uintptr_t> sEchmoduleApiSet;

		// @note: @colby57: Iterate through the patch information vector using a range-based loop.
		for (const auto& sIatPatchInfo : vecPatchInfo)
		{
			// @note: @colby57: Destructure the struct for better readability.
			const auto [ApiAddress, BaseModule] = std::tie(sIatPatchInfo.m_pApiAddress, sIatPatchInfo.m_pBaseModule);

			// @note: @colby57: Check if the base module matches the current import module.
			if (BaseModule == pImportModule)
				sEchmoduleApiSet.insert(ApiAddress);
		}

		ModuleInfo sTempModule{};

		// @note: @colby57: Get module path by address and populate sTempModule.
		GetModulePathByAddress(pImportModule, sTempModule);

		// @note: @colby57: Use emplace for more efficient insertion into the map.
		mapImportEchmoduleApi.emplace(pImportModule, std::move(sEchmoduleApiSet));

		char kBuffer[256];
		StringConversion::ToAscii(sTempModule.fullPath, kBuffer, sizeof(kBuffer));

		// @note: @colby57: Display module information in the log.
		spdlog::info("{0} -> {1:x}", kBuffer, pImportModule);
	}
}

bool VMPCore::SetPatchIatAddress()
{
	std::vector<std::uint8_t> vecIatContent(k32IatSize + 4);
	std::uintptr_t pBytesRead;

	// @note: @colby57: Read IAT content from the target process.
	if (!ReadProcessMemory(ProcessAccessHelp::hProcess, reinterpret_cast<void*>(pIatAddress), vecIatContent.data(), k32IatSize, &pBytesRead))
	{
		spdlog::error("Cannot read IAT content! Error: {}", GetLastError());

		vecIatContent.clear();
		vecIatContent.shrink_to_fit();

		return false;
	}

	bool Found = false;

	// @note: @colby57: Iterate through the patch information vector.
	for (auto& sIatPatchInfo : vecPatchInfo)
	{
		for (int i = 0; i < k32IatSize; i += sizeof(std::uintptr_t))
		{
			// @note: @colby57: Read data from the IAT content.
			std::uintptr_t data = *reinterpret_cast<std::uintptr_t*>(vecIatContent.data() + i);

			// @note: @colby57: Check if the data matches the API address in the patch information.
			if (data == sIatPatchInfo.m_pApiAddress)
			{
				// @note: @colby57: Set the IAT address in the patch information.
				sIatPatchInfo.m_pIatAddress = pIatAddress + i;
				Found = true;
				break;
			}
		}

		if (!Found)
			spdlog::error("Cannot find api address in new IAT? 0x{0:x}", sIatPatchInfo.m_pApiAddress);
	}

	vecIatContent.clear();
	vecIatContent.shrink_to_fit();

	return Found;
}

static void VMPCore::ApplyPatches()
{
	std::vector<std::uint8_t> vecCode(32);

	int iCodeLen{};
	std::uintptr_t WrittedBytes{};

	// @note: @colby57: Iterate through the patch information vector and apply patches.
	for (const auto& sIatPatchInfo : vecPatchInfo)
	{
		const auto iCallIatMode = sIatPatchInfo.m_iCallIatMode;

		// @note: @colby57: Check if the call mode is known.
		if (iCallIatMode != VMPCore::CALL_IAT_UNKNOWN)
		{
			// @note: @colby57: Assemble the call instruction.
			if (iCodeLen = ZydisWrapper::AssembleCall(
				vecCode.data(),
				vecCode.size(),
				iCallIatMode,
				sIatPatchInfo.m_pIatAddress,
				sIatPatchInfo.m_pPatchAddress,
				sIatPatchInfo.m_iRegIndex))
			{
				// @note: @colby57: Check if the assembled code is valid.
				if (iCodeLen == 5 || iCodeLen == 6 || (iCallIatMode == VMPCore::CALL_IAT_MOV_REFERENCE && iCodeLen == 7))
				{
					// @note: @colby57: Write the assembled code to the patch address.
					if (!WriteProcessMemory(ProcessAccessHelp::hProcess, reinterpret_cast<void*>(sIatPatchInfo.m_pPatchAddress), vecCode.data(), iCodeLen, &WrittedBytes))
					{
						spdlog::error("Cannot apply patch to: 0x{0:x}", sIatPatchInfo.m_pPatchAddress);
					}
				}
			}
			else
			{
				spdlog::error("Failed to assemble call from patch address: 0x{0:x}", sIatPatchInfo.m_pPatchAddress);
			}
		}
	}
}

bool VMPCore::RebuildIAT()
{
	int Num{};
	int Index{};
	std::uintptr_t WrittedBytes{};
	std::uintptr_t Buffer{};

	// @note: @colby57: Calculate the total number of entries in the IAT.
	for (auto ImportEchmoduleApi : mapImportEchmoduleApi)
		Num += ImportEchmoduleApi.second.size();

	Num += vecModuleList.size();

	k32IatSize = Num * sizeof(std::uintptr_t);
	std::size_t nSize = (k32IatSize / 0x1000 + 1) * 0x1000;

	DWORD dwOldProtect;

	// @note: @colby57: Change protection of the allocated memory to PAGE_READWRITE.
	if (VirtualProtectEx(ProcessAccessHelp::hProcess, (LPVOID)pIatAddress, nSize, PAGE_READWRITE, &dwOldProtect) == 0)
	{
		spdlog::error("Cannot change protect for new IAT");
		return false;
	}

	// @note: @colby57: Write API addresses to the new IAT.
	for (auto ImportEchmoduleApi : mapImportEchmoduleApi)
	{
		auto EachModuleApiSet = ImportEchmoduleApi.second;

		for (auto pApiAddress : EachModuleApiSet)
		{
			if (!WriteProcessMemory(
				ProcessAccessHelp::hProcess,
				(void*)(pIatAddress + Index * sizeof(std::uintptr_t)),
				&pApiAddress, sizeof(std::uintptr_t),
				&WrittedBytes))
			{
				spdlog::critical("[1] WriteProcessMemory failed: {}", GetLastError());
				return false;
			}

			Index += 1;
		}

		// @note: @colby57: Write a placeholder buffer after each module's API addresses.
		if (!WriteProcessMemory(
			ProcessAccessHelp::hProcess,
			(void*)((std::uintptr_t)pIatAddress + Index * sizeof(std::uintptr_t)),
			&Buffer, sizeof(std::uintptr_t),
			&WrittedBytes))
		{
			spdlog::critical("[2] WriteProcessMemory failed: {}", GetLastError());
			return false;
		}

		Index += 1;
	}

	spdlog::info("IAT Created. Address: {0:x}, Size: {1:x}", pIatAddress, k32IatSize);
	return true;
}

bool VMPCore::PatchCalls()
{
	// @note: @colby57: Check if the IAT section is specified.
	if (!bUseIatSection)
	{
		spdlog::error("Initialize error 1. Allocated memory won't work here. Use -i \"section_name\". Bruh!\n");
		return false;
	}

	// @note: @colby57: Attempt to rebuild the IAT.
	if (!RebuildIAT())
	{
		spdlog::error("Initialize error 2. Rebuild IAT failed!\n");
		return false;
	}

	// @note: @colby57: Set patch addresses for IAT.
	if (!SetPatchIatAddress())
	{
		spdlog::error("Initialize error 3. Failed to set patches.\n");
		return false;
	}

	spdlog::info("Fixing calls...\n");

	// @note: @colby57: Apply the patches to E8 calls.
	ApplyPatches();
	return true;
}

std::vector<std::string> GetVmpSections(ProcessMemory& sMemory)
{
	// @note: @colby57: Calculate entropy for the given section
	auto CalculateEntropy = [&](IMAGE_SECTION_HEADER Section)
		{
			const auto CalculatedVirtualAddress = (VMPCore::pImageLoadAddress + Section.VirtualAddress);
			const auto BufferSize = Section.Misc.VirtualSize;

			double Entropy{};

			// @note: @colby57: Read section data into a buffer
			std::vector<std::uint8_t> vecBuffer(BufferSize);
			sMemory.Read(CalculatedVirtualAddress, BufferSize, vecBuffer.data());

			std::map<std::uint8_t, double> mapByteProbabilities;
			std::map<std::uint8_t, int> mapByteFrequencies;

			// @note: @colby57: Calculate byte frequencies in the section
			for (const auto& byte : vecBuffer)
				mapByteFrequencies[byte]++;

			// @note: @colby57: Calculate byte probabilities in the section
			for (const auto& pair : mapByteFrequencies)
				mapByteProbabilities[pair.first] = static_cast<double>(pair.second) / BufferSize;

			// @note: @colby57: Calculate entropy using byte probabilities
			for (const auto& pair : mapByteProbabilities)
				Entropy -= pair.second * log2(pair.second);

			// @note: @colby57: Clear and shrink vectors to free memory
			vecBuffer.clear();
			vecBuffer.shrink_to_fit();

			mapByteFrequencies.clear();
			mapByteProbabilities.clear();

			return Entropy;
		};

	double Entropy{};

	std::vector<std::string> vecVmpSections{};

	// @note: @colby57: Iterate through the process sections
	for (const auto Section : VMPCore::vecProcessSections)
	{
		// @note: @colby57: Check if the section is executable
		if (Section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			spdlog::info("Section name: {}", (char*)Section.Name);
			spdlog::info("Entropy: {}\n", Entropy = CalculateEntropy(Section));

			// @note: @colby57: Check if entropy indicates a potentially VMP-protected section
			// @note: @colby57: Files protected by VMProtect always show entropy above 7.
			if (Entropy > 7.0)
			{
				spdlog::warn("Potentially VMP section: {}\n", (char*)Section.Name);
				vecVmpSections.emplace_back((char*)Section.Name);
			}
		}
	}

	return vecVmpSections;
}

void CollectMovIatReferences(std::uintptr_t pImageBase, std::size_t uImageSize, void* pPeBuffer, const std::vector<ptr_t>& vecAddressResults)
{
	if (pPeBuffer == nullptr)
		return;

	auto* pImage = reinterpret_cast<std::uint8_t*>(pPeBuffer);

	for (const auto& Result : vecAddressResults)
	{
		const auto PatchAddress = static_cast<std::uintptr_t>(Result);

		const auto Offset = PatchAddress - pImageBase;
		auto* pInstruction = pImage + Offset;

		if ((pInstruction[0] != 0x48 && pInstruction[0] != 0x4C) || pInstruction[1] != 0x8B)
			continue;

		S_DisasmWrapper sDisasm{};
		if (!ZydisWrapper::Disasm64(sDisasm, reinterpret_cast<std::uintptr_t>(pInstruction), 7))
			continue;


		if (sDisasm.m_sInstruction.mnemonic != ZYDIS_MNEMONIC_MOV || sDisasm.m_sInstruction.operand_count < 2)
			continue;

		const auto& op = sDisasm.m_sOperands[0];
		if (op.type != ZYDIS_OPERAND_TYPE_REGISTER /*|| op.mem.base != ZYDIS_REGISTER_CS*/)
			continue;

		if (sDisasm.m_sOperands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
			continue;

		if (!sDisasm.m_sOperands[1].mem.disp.has_displacement)
			continue;

		if (sDisasm.m_sOperands[1].mem.base != ZYDIS_REGISTER_RIP)
			continue;

		const std::uintptr_t RipNext = PatchAddress + sDisasm.m_sInstruction.length;
		const std::int64_t Displacement = sDisasm.m_sOperands[1].mem.disp.value;


		const auto SlotAddress = static_cast<std::uintptr_t>(
			static_cast<std::int64_t>(RipNext) + Displacement
			);

		if (SlotAddress < pImageBase || SlotAddress + sizeof(std::uintptr_t) > pImageBase + uImageSize)
			continue;

		const auto SlotOffset = SlotAddress - pImageBase;


		const auto ApiAddress = *reinterpret_cast<std::uintptr_t*>(pImage + SlotOffset);

		if (ApiAddress == 0)
			continue;

		bool is_suspected = false;
		auto api = VMPCore::sApiReader.getApiByVirtualAddress(ApiAddress, &is_suspected);

		if (api == 0)
			continue;

		if (api->module->modBaseAddr == pImageBase || api->module->modBaseAddr == reinterpret_cast<std::uintptr_t>(pImage))
			continue;


		VMPCore::S_IatPatchInfo PatchInfo{};

		PatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_MOV_REFERENCE;
		PatchInfo.m_pPatchAddress = PatchAddress;
		PatchInfo.m_pBaseModule = api->module->modBaseAddr;
		PatchInfo.m_pApiAddress = ApiAddress;

		PatchInfo.m_iRegIndex = op.reg.value;

		VMPCore::vecPatchInfo.emplace_back(std::move(PatchInfo));
		spdlog::info("MOV IAT reference detected at 0x{0:x} targeting 0x{1:x} - {2}", PatchAddress, ApiAddress, api->name);
	}
}


void CollectDirectIatCalls(std::uintptr_t pImageBase, std::size_t uImageSize, void* pPeBuffer, const std::vector<ptr_t>& vecAddressResults)
{
	if (pPeBuffer == nullptr)
		return;

	auto* pImage = reinterpret_cast<std::uint8_t*>(pPeBuffer);

	for (const auto& Result : vecAddressResults)
	{
		const auto PatchAddress = static_cast<std::uintptr_t>(Result);

		if (PatchAddress < pImageBase || PatchAddress + 6 > pImageBase + uImageSize)
			continue;

		const auto Offset = PatchAddress - pImageBase;
		auto* pInstruction = pImage + Offset;

		if (pInstruction[0] != 0xFF || pInstruction[1] != 0x15)
			continue;

		const auto Displacement = *reinterpret_cast<std::int32_t*>(pInstruction + 2);
		const auto RipNext = PatchAddress + 6;
		const auto SlotAddressSigned = static_cast<std::int64_t>(RipNext) + static_cast<std::int64_t>(Displacement);

		if (SlotAddressSigned < 0)
			continue;

		const auto SlotAddress = static_cast<std::uintptr_t>(SlotAddressSigned);

		if (SlotAddress < pImageBase || SlotAddress + sizeof(std::uintptr_t) > pImageBase + uImageSize)
			continue;

		const auto SlotOffset = SlotAddress - pImageBase;
		const auto ApiAddress = *reinterpret_cast<std::uintptr_t*>(pImage + SlotOffset);

		if (ApiAddress == 0)
			continue;

		bool is_suspected = false;

		auto api = VMPCore::sApiReader.getApiByVirtualAddress(ApiAddress, &is_suspected);

		if (api == 0)
			continue;

		const auto AlreadyExists = std::any_of(
			VMPCore::vecPatchInfo.begin(),
			VMPCore::vecPatchInfo.end(),
			[PatchAddress](const VMPCore::S_IatPatchInfo& Info)
			{
				return Info.m_pPatchAddress == PatchAddress;
			});

		if (AlreadyExists)
			continue;

		VMPCore::S_IatPatchInfo PatchInfo{};
		PatchInfo.m_iCallIatMode = VMPCore::CALL_IAT_COMMON;
		PatchInfo.m_iIatEncryptMode = VMPCore::IAT_ENCRYPT_UNKNOWN;
		PatchInfo.m_pPatchAddress = PatchAddress;
		PatchInfo.m_pBaseModule = api->module->modBaseAddr;
		PatchInfo.m_pApiAddress = ApiAddress;

		VMPCore::vecPatchInfo.emplace_back(std::move(PatchInfo));
		spdlog::info("Direct IAT call detected at 0x{0:x} targeting 0x{1:x} - {2}", PatchAddress, ApiAddress, api->name);
	}
}


int main(int argc, char** argv)
{
	argparse::ArgumentParser cProgram("VMP-Imports-Deobfuscator");

	cProgram.add_argument("-p", "--pid")
		.help("Target process name")
		.required()
		.scan<'d', int>();

	cProgram.add_argument("-m", "--module")
		.help("Target module name")
		.default_value<std::string>("");

	cProgram.add_argument("-i", "--iat")
		.help("section that is used to storage new IAT, it maybe destroy vmp code")
		.default_value<std::string>(".rdata");

	try
	{
		cProgram.parse_args(argc, argv);
	}
	catch (const std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
		std::cerr << cProgram;
		std::exit(1);
	}

	// @note: @colby57: Retrieve values of parsed command line arguments.
	auto iProcessId = cProgram.get<int>("--pid");
	auto sNewIat = cProgram.get<std::string>("--iat");
	auto sModuleName = cProgram.get<std::string>("--module");

	Process sProcess{};

	// @note: @colby57: Attempt to attach to the target process.
	if (NT_SUCCESS(sProcess.Attach(iProcessId)))
	{
		// @note: @colby57: Access the target process memory and modules.
		auto& sMemory = sProcess.memory();
		auto& sModules = sProcess.modules();

		auto& sCore = sProcess.core();

		// @note: @colby57: Check if process is 32-bit
		if (sCore.isWow64())
		{
			spdlog::error("32-bit applications are not yet supported!\n");
			sProcess.Detach();
			return 0;
		}

		// @note: @colby57: Get information about the target module.
		auto sTargetModule = sModuleName == "" ? sModules.GetMainModule() : sModules.GetModule(std::wstring(sModuleName.begin(), sModuleName.end()));

		if (!sTargetModule)
		{
			spdlog::error("Failed to find module {} in process", sModuleName.c_str());
			return 0;
		}

		// @note: @colby57: Allocate a buffer to store the PE image of the target module.
		const auto pBuffer = malloc(sTargetModule->size);

		if (!pBuffer)
		{
			spdlog::error("Allocate PE Image buffer failed");
			return 0;
		}

		// @note: @colby57: Initialize global variables with module information.
		VMPCore::pImageLoadAddress = sTargetModule->baseAddress;
		VMPCore::k32ImageSize = sTargetModule->size;
		VMPCore::pImageBuffer = reinterpret_cast<std::uintptr_t>(pBuffer);

		// @note: @colby57: Read the target module's data into the buffer.
		if (NT_SUCCESS(sMemory.Read(sTargetModule->baseAddress, sTargetModule->size, pBuffer)))
		{
			// @note: @colby57: Parse the PE image to extract information about its sections.
			PEImage sPeImage;
			sPeImage.Parse(pBuffer);

			for (auto sSection : sPeImage.sections())
				VMPCore::vecProcessSections.emplace_back(sSection);

			const auto sExcludeSections = GetVmpSections(sMemory);

			// @note: @colby57: Locate the section for the new IAT within the PE image.
			for (auto& sSection : sPeImage.sections())
			{
				const auto result = strncmp(sNewIat.c_str(), (char*)sSection.Name, sNewIat.length());

				if (result == 0)
				{
					spdlog::info("IAT Allocated in {}", sNewIat.c_str());
					VMPCore::bUseIatSection = true;
					VMPCore::pIatAddress = VMPCore::pImageLoadAddress + sSection.VirtualAddress;
					break;
				}
			}

			if (!VMPCore::bUseIatSection)
			{
				spdlog::critical("Section for new IAT is not found!");
				free(pBuffer);
				return 0;
			}

			// @note: @colby57: Iterate through sections, searching for specific patterns and filtering addresses.
			for (auto sSection : sPeImage.sections())
			{
				if ((sSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
					std::find(sExcludeSections.begin(), sExcludeSections.end(), (char*)sSection.Name) == sExcludeSections.end())
				{
					// @note: @colby57: Search for a specific pattern in the target section.
					{
						PatternSearch sPattern({ 0xE8,'?','?','?','?' });
						std::vector<ptr_t> vecResults{};

						if (sPattern.SearchRemote(
							sProcess,
							'?',
							sTargetModule->baseAddress + sSection.VirtualAddress,
							sSection.Misc.VirtualSize,
							vecResults,
							SIZE_MAX) != 0)
						{
							// @note: @colby57: Filter addresses based on certain criteria.
							FilterAddresses(
								sTargetModule->baseAddress,
								sTargetModule->size,
								pBuffer,
								VMPCore::vecPatternAddressList,
								vecResults,
								sSection.VirtualAddress,
								sSection.Misc.VirtualSize);
						}
					}



				}
			}

			sProcess.Detach();

			// @note: @colby57: Initialize the Unicorn emulator with the PE image buffer.
			const auto Status = Emulator::Init(pBuffer);

			if (!Status)
			{
				spdlog::error("Cannot initialize emulator.\n");
				free(pBuffer);
				return 0;
			}

			// @note: @colby57: Open a handle to the target process and retrieve module information.
			if (!ProcessAccessHelp::openProcessHandle(iProcessId))
			{
				spdlog::error("Open Process Failed\n");
				free(pBuffer);
				return 0;
			}

			// @note: @colby57: Retrieve module information from the current and target processes.
			if (!ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList) ||
				!ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList))
			{
				spdlog::error("Cannot get process modules\n");
				ProcessAccessHelp::closeProcessHandle();
				free(pBuffer);
			}

			// @note: @colby57: Read APIs from module list and store in the ApiReader instance.
			VMPCore::sApiReader.readApisFromModuleList();

			// @note: @colby57: Emulate patterns for each specified pattern address.
			for (auto Address : VMPCore::vecPatternAddressList)
			{
				VMPCore::pCurrentPatternAddress = Address;
				Emulator::Start(VMPCore::pCurrentPatternAddress);
			}



			// @note: @baier233: Locate the unencrypted IAT calls, add them to the new IAT table, and subsequently redirect the addresses of the IAT calls to the new IAT table.
			sProcess.Attach(iProcessId);

			for (auto sSection : sPeImage.sections())
			{
				if ((sSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
					std::find(sExcludeSections.begin(), sExcludeSections.end(), (char*)sSection.Name) == sExcludeSections.end())
				{

					{

						PatternSearch sPattern({ 0XFF,0X15,'?','?','?','?' });
						std::vector<ptr_t> vecDirectCallResults{};

						if (sPattern.SearchRemote(
							sProcess,
							'?',
							sTargetModule->baseAddress + sSection.VirtualAddress,
							sSection.Misc.VirtualSize,
							vecDirectCallResults,
							SIZE_MAX) != 0)
						{

							CollectDirectIatCalls(sTargetModule->baseAddress,
								sTargetModule->size,
								pBuffer,
								vecDirectCallResults);
						}
					}
					MessageBox(0, 0, 0, 0);
					{
						PatternSearch sPattern48({ 0X48, 0X8B, '?', '?', '?', '?', '?' });
						std::vector<ptr_t> vecMovResults{};

						if (sPattern48.SearchRemote(
							sProcess,
							'?',
							sTargetModule->baseAddress + sSection.VirtualAddress,
							sSection.Misc.VirtualSize,
							vecMovResults,
							SIZE_MAX) != 0)
						{
							CollectMovIatReferences(
								sTargetModule->baseAddress,
								sTargetModule->size,
								pBuffer,
								vecMovResults);
						}

						PatternSearch sPattern4C({ 0X4C, 0X8B, '?', '?', '?', '?', '?' });
						std::vector<ptr_t> vecMovResults4C{};

						if (sPattern4C.SearchRemote(
							sProcess,
							'?',
							sTargetModule->baseAddress + sSection.VirtualAddress,
							sSection.Misc.VirtualSize,
							vecMovResults4C,
							SIZE_MAX) != 0)
						{
							CollectMovIatReferences(
								sTargetModule->baseAddress,
								sTargetModule->size,
								pBuffer,
								vecMovResults4C);
						}
					}


				}
			}

			sProcess.Detach();



			// @note: @colby57: Retrieve information about IAT modules, import module API lists, and fix IAT in memory.
			VMPCore::ParseModules();
			VMPCore::ParseApiList();

			if (!VMPCore::PatchCalls())
			{
				spdlog::critical("bruh!");

				ProcessAccessHelp::closeProcessHandle();
				free(pBuffer);

				return 0;
			}
		}
		else
		{
			spdlog::error("Failed to read PE Image!");

			ProcessAccessHelp::closeProcessHandle();
			free(pBuffer);

			return 0;
		}
	}
	else
	{
		spdlog::error("Attach Failed\n");
		return 0;
	}

	spdlog::info("All imports fixed! Enjoy!");
	return 0;
}