use process_spoofer::{spoof_arguments, spoof_ppid};

fn main() {
    spoof_arguments();
    spoof_ppid(5868);
}
