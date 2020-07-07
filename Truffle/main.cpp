#include "argparse.h"
#include "W32Fuzzer.h"

#define BUILD_VERSION "0.1"

int main(int argc, char* argv[]) {

	// Example usage:
	// truffle.exe -dll ntdll.dll 
	// truffle.exe -dll ntdll.dll -t 6000

	argparse::ArgumentParser p("Truffle", BUILD_VERSION);

	p.add_argument("dll")
		.help("Win32 dll name to scan. Uses GetModuleHandle then LoadLibrary. (e.g. crypt32.dll)");

	p.add_argument("-t")
		.help("Sets the timeout in ms for the thread of each. The default timeout is 1000ms.")
		.default_value(1000)
		.action([](const std::string& value) { return std::stoi(value); });

	try {
		p.parse_args(argc, argv);
	}
	catch (const std::runtime_error& err) {
		std::cout << err.what() << std::endl;
		std::cout << p;
		exit(0);
	}

	auto libToScan = p.get<string>("dll");
	auto timeout = p.get<int>("-t");

	printf_s("Initiating scan on module %s with timeout %d\n", libToScan.c_str(), timeout);

	auto fuzz = new W32Fuzzer(libToScan.c_str());

	// Set timeout in ms for the fuzzed function
	// A lot of functions won't finish executing and hang indefinitely given
	//	a) an incorrect number of arguments
	//	b) random parameters
	fuzz->SetTimeout(timeout);

	// Install the VEH so we can call functions with random parameters
	fuzz->SetVectoredHook();

	// Push 16 DWORDs (no function has more, except some __cdecl functions,
	// 99% of WinAPI functions are __stdcall (also hence the registers chosen to preserve
	fuzz->GetProcLengths();

	// Once we know how many arguments the function legally accepts
	// Push that number of arguments to the function and see it if finishes executing
	// If so, save the registers that are preserved during a __stdcall function
	fuzz->FuzzAPI_Round1();

	// Repeat the process in Round1 with different random arguments
	fuzz->FuzzAPI_Round2();

	// Compare round 1 & round 2 results and look for any matching register artifacts
	fuzz->Analyze();

	// Uninstall VEH
	fuzz->removeVectoredHook();

	return 0;
}