
#include "Wrapper.h"
#include "../../VMPCore.h"

std::uintptr_t ZydisWrapper::CalculateAbsoluteAddr(S_DisasmWrapper& sDisasm, std::size_t nOperandSize)
{
	std::uintptr_t pOut;

	ZydisCalcAbsoluteAddress(
		&sDisasm.m_sInstruction,
		&sDisasm.m_sOperands[nOperandSize],
		sDisasm.m_pRuntimeAddr,
		&pOut);

	return pOut;
}

void ZydisWrapper::AppendInstruction(const ZydisEncoderRequest* pEncoderRequest, ZyanU8** Buffer, ZyanUSize* BufferLength)
{
	ZyanUSize InstrLength = *BufferLength;
	ZydisEncoderEncodeInstruction(pEncoderRequest, *Buffer, &InstrLength);

	*Buffer += InstrLength;
	*BufferLength -= InstrLength;
}

bool ZydisWrapper::Disasm(S_DisasmWrapper& sDisasm, std::uintptr_t pData, int iLen)
{
	ZydisDecoder sDecoder{};
	ZydisDecoderInit(&sDecoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

	ZydisFormatter sFormatter{};
	ZydisFormatterInit(&sFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

	auto pRuntimeAddr = sDisasm.m_pRuntimeAddr;
	ZyanUSize nOffset{};

	if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&sDecoder,
		(void*)(pData + nOffset),
		iLen - nOffset,
		&sDisasm.m_sInstruction,
		sDisasm.m_sOperands,
		ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
		ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
		return true;
	else
		return false;
}

bool ZydisWrapper::Disasm64(S_DisasmWrapper& sDisasm, std::uintptr_t pData, int iLen)
{
	ZydisDecoder sDecoder{};
	ZydisDecoderInit(&sDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisFormatter sFormatter{};
	ZydisFormatterInit(&sFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

	auto pRuntimeAddr = sDisasm.m_pRuntimeAddr;
	ZyanUSize nOffset{};

	if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&sDecoder,
		(void*)(pData + nOffset),
		iLen - nOffset,
		&sDisasm.m_sInstruction,
		sDisasm.m_sOperands,
		2,
		ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
		return true;
	else
		return false;
}

#include <spdlog/spdlog.h>

ZyanUSize ZydisWrapper::AssembleCall(ZyanU8* Buffer, ZyanUSize BufferLength, int CallIatMode, std::uintptr_t IatAddress, std::uintptr_t PatchAddress, int RegIndex)
{
	ZyanU8* pWritePtr = Buffer;
	ZyanUSize RemainingLength = BufferLength;
	ZydisEncoderRequest sEncoderRequest{};
	std::memset(&sEncoderRequest, 0, sizeof(sEncoderRequest));

	sEncoderRequest.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;

	switch (CallIatMode)
	{
	case VMPCore::CALL_IAT_COMMON:
		sEncoderRequest.mnemonic = ZYDIS_MNEMONIC_CALL;
		sEncoderRequest.operand_count = 1;
		sEncoderRequest.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
		sEncoderRequest.operands[0].mem.size = sizeof(std::uintptr_t);
		sEncoderRequest.operands[0].mem.base = ZYDIS_REGISTER_RIP;
		sEncoderRequest.operands[0].mem.displacement = IatAddress - PatchAddress - 6;
		break;

	case VMPCore::CALL_IAT_JMP:
		sEncoderRequest.mnemonic = ZYDIS_MNEMONIC_JMP;
		sEncoderRequest.operand_count = 1;
		sEncoderRequest.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
		sEncoderRequest.operands[0].mem.size = sizeof(std::uintptr_t);
		sEncoderRequest.operands[0].mem.base = ZYDIS_REGISTER_RIP;
		sEncoderRequest.operands[0].mem.displacement = IatAddress - PatchAddress - 6;
		break;

		// @note: @baier233: It should be compiled for x64. Moreover, the length of the assembled instructions is 7.
	case VMPCore::CALL_IAT_MOV_REG:
		sEncoderRequest.mnemonic = ZYDIS_MNEMONIC_MOV;
		sEncoderRequest.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
		sEncoderRequest.operand_count = 2;
		sEncoderRequest.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
		sEncoderRequest.operands[0].reg.value = (ZydisRegister)(ZYDIS_REGISTER_RAX + RegIndex);
		sEncoderRequest.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		sEncoderRequest.operands[1].mem.size = sizeof(std::uintptr_t);
		sEncoderRequest.operands[1].mem.displacement = IatAddress - PatchAddress - 7;;
		sEncoderRequest.operands[1].mem.base = ZYDIS_REGISTER_RIP;

		break;
	case VMPCore::CALL_IAT_MOV_REFERENCE:
		sEncoderRequest.mnemonic = ZYDIS_MNEMONIC_MOV;
		sEncoderRequest.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
		sEncoderRequest.operand_count = 2;
		sEncoderRequest.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
		sEncoderRequest.operands[0].reg.value = (ZydisRegister)RegIndex;
		sEncoderRequest.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		sEncoderRequest.operands[1].mem.size = sizeof(std::uintptr_t);
		sEncoderRequest.operands[1].mem.base = ZYDIS_REGISTER_RIP;
		sEncoderRequest.operands[1].mem.displacement = IatAddress - PatchAddress - 7;

		break;
	default:
		break;
	}

	AppendInstruction(&sEncoderRequest, &pWritePtr, &RemainingLength);
	return BufferLength - RemainingLength;
}