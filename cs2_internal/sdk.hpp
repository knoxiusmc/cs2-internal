#include "memory.hpp"
#include "AutoUpdater.hpp"

struct Offsets
{
	// offsets.hpp
	uintptr_t dwBuildNumber;
	uintptr_t dwLocalPlayerPawn;
	uintptr_t dwEntityList;

	// client_dll.hpp
	uintptr_t m_hPlayerPawn;
	uintptr_t m_iHealth;
	uintptr_t m_iTeamNum;

	uintptr_t m_Glow;
	uintptr_t m_iGlowType;
	uintptr_t m_glowColorOverride;
	uintptr_t m_bGlowing;
}; inline Offsets offsets{};

class c_SDK
{
private:
	bool didnt_fail = true;
#ifndef _WINDLL
	void print_offset(const std::string& name, uintptr_t offset)
	{
		std::cout << name << " " << std::showbase << std::hex << offset << std::endl;
	}
#endif
	void update_offset(URLSession& session, const std::string& name, uintptr_t& outOffset, int fileType)
	{
		std::string formattedName = name;

		if (fileType == 2 && name.rfind(xorstr_("constexpr std::ptrdiff_t "), 0) != 0)
			formattedName = xorstr_("constexpr std::ptrdiff_t ") + name + " = ";

		outOffset = getAddress(session, formattedName, fileType);

		if (!outOffset)
			didnt_fail = false;

#ifndef _WINDLL
			print_offset(name, outOffset);
#endif
	}
public:
	std::shared_ptr<pProcess> process;
	ProcessModule client_dll;
	ProcessModule engine_dll;

	void GetClientBase()
	{
		while (!client_dll.base)
		{
			client_dll = process->GetModule(xorstr_("client.dll"));
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}
	void GetEngineBase()
	{
		while (!engine_dll.base)
		{
			engine_dll = process->GetModule(xorstr_("engine2.dll"));
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}

	bool UpdateOffsets()
	{
		URLSession session;

		// Grouped for readability
		update_offset(session, xorstr_("dwBuildNumber"), offsets.dwBuildNumber, 1);
		update_offset(session, xorstr_("dwLocalPlayerPawn"), offsets.dwLocalPlayerPawn, 1);
		update_offset(session, xorstr_("dwEntityList"), offsets.dwEntityList, 1);

		update_offset(session, xorstr_("m_hPlayerPawn"), offsets.m_hPlayerPawn, 2);
		update_offset(session, xorstr_("m_iHealth"), offsets.m_iHealth, 2);
		update_offset(session, xorstr_("m_iTeamNum"), offsets.m_iTeamNum, 2);

		update_offset(session, xorstr_("m_Glow"), offsets.m_Glow, 2);
		update_offset(session, xorstr_("m_iGlowType"), offsets.m_iGlowType, 2);
		update_offset(session, xorstr_("m_glowColorOverride"), offsets.m_glowColorOverride, 2);
		update_offset(session, xorstr_("m_bGlowing"), offsets.m_bGlowing, 2);

		std::this_thread::sleep_for(std::chrono::milliseconds(25));
		closeWeb(session);

		return didnt_fail;
	}
}; inline c_SDK SDK{};