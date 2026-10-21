#include <windows.h>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command) {
    (void)instance;
    (void)previous;
    (void)command_line;
    (void)show_command;
    MessageBoxW(NULL,
                L"Look ma, incredibly weak private keys!",
                L"eMudhra CA Compromise Lab",
                MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    return 0;
}
