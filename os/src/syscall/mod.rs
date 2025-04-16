//! Implementation of syscalls
//!
//! The single entry point to all system calls, [`syscall()`], is called
//! whenever userspace wishes to perform a system call using the `ecall`
//! instruction. In this case, the processor raises an 'Environment call from
//! U-mode' exception, which is handled as one of the cases in
//! [`crate::trap::trap_handler`].
//!
//! For clarity, each single syscall is implemented as its own function, named
//! `sys_` then the name of the syscall. You can find functions like this in
//! submodules, and you should also implement syscalls this way.

/// write syscall
const SYSCALL_WRITE: usize = 64;
/// exit syscall
const SYSCALL_EXIT: usize = 93;
/// yield syscall
const SYSCALL_YIELD: usize = 124;
/// gettime syscall
const SYSCALL_GET_TIME: usize = 169;
/// trace syscall
const SYSCALL_TRACE: usize = 410;

mod fs;
mod process;

use fs::*;
use process::*;
use crate::task::TASK_MANAGER;

/// handle syscall exception with `syscall_id` and other arguments
pub fn syscall(syscall_id: usize, args: [usize; 3]) -> isize {
    // 记录系统调用，除了sys_trace，因为对于sys_trace需要考虑trace_request为2的情况
    if syscall_id < crate::config::MAX_SYSCALL_NUM && syscall_id != SYSCALL_TRACE {
        TASK_MANAGER.increment_current_task_syscall_times(syscall_id);
    }
    
    // 根据系统调用ID调用对应的处理函数
    match syscall_id {
        SYSCALL_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => sys_exit(args[0] as i32),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_GET_TIME => sys_get_time(args[0] as *mut TimeVal, args[1]),
        SYSCALL_TRACE => {
            // 对于sys_trace，在这里记录调用
            TASK_MANAGER.increment_current_task_syscall_times(SYSCALL_TRACE);
            
            sys_trace(args[0], args[1], args[2])
        },
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
