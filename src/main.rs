use process_spoofer::{spoof_arguments, spoof_ppid, apply_process_mitigation_policy};

fn main() {
    spoof_arguments();
    spoof_ppid(5868);
    apply_process_mitigation_policy();
}
