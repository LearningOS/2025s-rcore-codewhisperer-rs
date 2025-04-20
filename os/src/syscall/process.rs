//! Process management syscalls
use crate::task::{change_program_brk, exit_current_and_run_next, suspend_current_and_run_next};
use crate::task::{current_task, current_user_token};
use crate::timer::get_time_us;
use crate::mm::{translated_byte_buffer, MapPermission, VirtAddr, PageTable, VPNRange};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    
    // 检查用户提供的地址是否有效且可写
    let va = VirtAddr::from(ts as usize);
    let time_val_size = core::mem::size_of::<TimeVal>();
    let end_va = VirtAddr::from(ts as usize + time_val_size - 1);
    
    // 检查起始地址和结束地址所在的页面是否都可写
    for vpn in VPNRange::new(va.floor(), end_va.floor() + 1) {
        if let Some(pte) = page_table.translate(vpn) {
            if !pte.is_valid() || !pte.writable() || !pte.user_accessible() {
                return -1;
            }
        } else {
            return -1;
        }
    }
    
    // 使用 translated_byte_buffer 安全地写入数据
    let buffers = translated_byte_buffer(token, ts as *const u8, time_val_size);
    let mut total_len = 0;
    let time_val_bytes = unsafe {
        core::slice::from_raw_parts(
            &time_val as *const TimeVal as *const u8,
            time_val_size
        )
    };
    
    for buffer in buffers {
        let len = buffer.len().min(time_val_bytes.len() - total_len);
        buffer[..len].copy_from_slice(&time_val_bytes[total_len..total_len + len]);
        total_len += len;
        if total_len >= time_val_bytes.len() {
            break;
        }
    }
    
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    
    match trace_request {
        // 读取用户程序中指定地址处的一个字节
        0 => {
            let token = current_user_token();
            let page_table = PageTable::from_token(token);
            let va = VirtAddr::from(id);
            
            // 检查地址是否可读
            if let Some(pte) = page_table.translate(va.floor()) {
                if !pte.is_valid() || !pte.readable() || !pte.user_accessible() {
                    return -1;
                }
            } else {
                return -1;
            }
            
            // 使用 translated_byte_buffer 安全地读取数据
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] as isize
        },
        // 写入用户程序中指定地址处的一个字节
        1 => {
            let token = current_user_token();
            let page_table = PageTable::from_token(token);
            let va = VirtAddr::from(id);
            
            // 检查地址是否可写
            if let Some(pte) = page_table.translate(va.floor()) {
                if !pte.is_valid() || !pte.writable() || !pte.user_accessible() {
                    return -1;
                }
            } else {
                return -1;
            }
            
            // 使用 translated_byte_buffer 安全地写入数据
            let mut buffers = translated_byte_buffer(token, id as *mut u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] = data as u8;
            0
        },
        // 查询当前任务系统调用的次数
        2 => {
            if id < 500 {
                let task = current_task();
                task.syscall_times[id] as isize
            } else {
                -1
            }
        },
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap, start={:#x}, len={}, port={:#x}", start, len, port);
    
    // Check alignment
    if start % crate::config::PAGE_SIZE != 0 {
        error!("sys_mmap: start address not page aligned");
        return -1;
    }
    
    // Check port flags validity
    if port & !0x7 != 0 || port & 0x7 == 0 {
        error!("sys_mmap: invalid port flags {:#x}", port);
        return -1;
    }
    
    // Calculate page-aligned length
    let actual_len = if len == 0 { 0 } else { crate::mm::page_ceil(len) };
    if actual_len == 0 {
        return 0;
    }
    
    // Convert port flags to MapPermission
    let mut permission = MapPermission::U; // User accessible is required
    if (port & 0x1) != 0 { permission |= MapPermission::R; } // Readable
    if (port & 0x2) != 0 { permission |= MapPermission::W; } // Writable
    if (port & 0x4) != 0 { permission |= MapPermission::X; } // Executable
    
    let task = current_task();
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + actual_len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    
    let memory_set = &mut task.memory_set;

    // Check for overlap
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if memory_set.translate(vpn).is_some() {
            error!("sys_mmap: address range [{:#x}, {:#x}) overlaps with existing mapping", start, start + actual_len);
            return -1; // Overlap error
        }
    }
    
    // Attempt to insert the new memory area.
    // Note: This function might panic if frame allocation fails.
    // A more robust implementation would handle potential allocation failures gracefully.
    memory_set.insert_framed_area(start_va, end_va, permission);
    trace!("sys_mmap: successfully mapped [{:#x}, {:#x})", start, start + actual_len);
    0 // Success
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap, start={:#x}, len={}", start, len);
    
    // Check alignment
    if start % crate::config::PAGE_SIZE != 0 {
        error!("sys_munmap: start address not page aligned");
        return -1;
    }
    
    // Calculate page-aligned length
    let actual_len = if len == 0 { 0 } else { crate::mm::page_ceil(len) };
    if actual_len == 0 {
        return 0;
    }
    
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + actual_len);
    let start_vpn = start_va.floor(); 
    let end_vpn = end_va.ceil(); 
    
    let task = current_task();
    let memory_set = &mut task.memory_set;
    
    // Restore the check for unmapped pages within the range, as per munmap specification.
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if memory_set.translate(vpn).is_none() {
            error!("sys_munmap: address range [{:#x}, {:#x}) contains unmapped page {:?}", start, start + actual_len, vpn);
            return -1;
        }
    }
    
    // Use remove_area_with_start_vpn to unmap the area
    // Note: Current implementation of remove_area_with_start_vpn always returns true.
    if memory_set.remove_area_with_start_vpn(start_va, end_va) {
         trace!("sys_munmap: successfully unmapped [{:#x}, {:#x})", start, start + actual_len);
         0 // Success
    } else {
        // This branch is likely unreachable with the current remove_area_with_start_vpn implementation.
        error!("sys_munmap: failed to remove area [{:#x}, {:#x})", start, start + actual_len);
        -1 // Removal failed
    }
}

/// Suspend the current task for the given number of ticks.
pub fn sys_sleep(ticks: usize) -> isize {
    trace!("kernel: sys_sleep, ticks={}", ticks);
    let start_tick = crate::timer::get_time(); // Get current time in ticks
    let target_tick = start_tick + ticks;
    while crate::timer::get_time() < target_tick {
        // Suspend the current task and let the scheduler run other tasks.
        // The task will be woken up later by the timer interrupt handler
        // or other events, and will re-check the condition.
        suspend_current_and_run_next();
    }
    0 // Return 0 on success
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}