#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstddef>



uintptr_t patternScan(HMODULE module, const char* pattern) {

	if (!module)
		return 0;

	MODULEINFO info{};

	if (!GetModuleInformation(
		GetCurrentProcess(),
		module,
		&info,
		sizeof(info)))
	{
		return 0;
	}

	auto* base = reinterpret_cast<uint8_t*>(info.lpBaseOfDll);
	size_t size = static_cast<size_t>(info.SizeOfImage);

	auto hex = [](char c) -> int
	{
		if (c >= '0' && c <= '9')
			return c - '0';

		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;

		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;

		return -1;
	};

	// Calculate pattern length.
	size_t patternLength = 0;

	for (const char* p = pattern; *p;)
	{
		while (*p == ' ')
			++p;

		if (!*p)
			break;

		++patternLength;

		while (*p && *p != ' ')
			++p;
	}

	if (patternLength == 0 || patternLength > size)
		return 0;

	for (size_t offset = 0;
		offset <= size - patternLength;
		++offset)
	{
		const char* p = pattern;
		size_t j = 0;

		while (*p && j < patternLength)
		{
			while (*p == ' ')
				++p;

			if (!*p)
				break;

			// Wildcard
			if (*p == '?')
			{
				++p;

				// Support both ? and ??
				if (*p == '?')
					++p;
			}
			else
			{
				int hi = hex(*p++);
				int lo = hex(*p++);

				if (hi < 0 || lo < 0)
					break;

				uint8_t byte =
					static_cast<uint8_t>((hi << 4) | lo);

				if (base[offset + j] != byte)
					break;
			}

			++j;

			while (*p && *p != ' ')
				++p;
		}

		if (j == patternLength)
			return reinterpret_cast<uintptr_t>(base + offset);
	}

	return 0;
}