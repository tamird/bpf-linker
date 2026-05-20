// assembly-output: bpf-linker
// compile-flags: --crate-type cdylib -C link-arg=--emit=obj -C link-arg=--btf -C debuginfo=2

#![no_std]

extern crate btf;
extern crate btf_macros;

use core::panic::PanicInfo;

use btf_macros::btf;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}

#[btf]
pub struct load_weight {
    weight: u64,
}

#[btf]
pub struct sched_entity {
    load: load_weight,
}

#[btf]
pub struct task_struct {
    pid: i32,
    tgid: i32,
    se: sched_entity,
}

mod bindings {
    #[repr(C)]
    pub struct task_struct {
        pub opaque: u8,
    }
}

// CHECK: Core reloc section #0 'uprobe/task_pid_plus_tgid':
// CHECK: #0: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:0: field_exists --> struct task_struct.pid
// CHECK: #1: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:0: byte_off --> struct task_struct.pid
// CHECK: #2: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:1: field_exists --> struct task_struct.tgid
// CHECK: #3: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:1: byte_off --> struct task_struct.tgid
// CHECK: #4: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:2:0:0: field_exists --> struct task_struct.se.load.weight
// CHECK: #5: core_reloc: insn #{{[0-9]+}} --> [{{[0-9]+}}] + 0:2:0:0: byte_off --> struct task_struct.se.load.weight

#[no_mangle]
#[link_section = "uprobe/task_pid_plus_tgid"]
pub unsafe extern "C" fn task_pid_plus_tgid(task: *const task_struct) -> i32 {
    let task = unsafe { &*task };
    let pid = task.pid().get().copied().unwrap_or(-1);
    let tgid = task.tgid().get().copied().unwrap_or(-1);
    let weight = task
        .se()
        .load()
        .weight()
        .get()
        .copied()
        .unwrap_or_default();

    pid + tgid + weight as i32
}

#[no_mangle]
#[link_section = "uprobe/opaque_task_struct"]
pub extern "C" fn opaque_task_struct(task: *const bindings::task_struct) -> bool {
    task.is_null()
}
