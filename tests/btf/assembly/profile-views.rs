// assembly-output: bpf-linker
// compile-flags: --crate-type cdylib -C link-arg=--emit=obj -C link-arg=--btf -C debuginfo=2

#![no_std]

extern crate btf;
extern crate btf_macros;

use core::panic::PanicInfo;

use btf::Profile as _;
use btf_macros::{btf, btf_profile};

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}

mod modern {
    use super::{btf, btf_profile};

    btf_profile! {
        pub struct Profile {
            detect {
                task_struct.__state,
            }
        }
    }

    // The included file represents generator output for one vmlinux flavor.
    include!("auxiliary/vmlinux-modern.rs");
}

mod legacy {
    use super::{btf, btf_profile};

    btf_profile! {
        pub struct Profile {
            detect {
                task_struct.state,
            }
        }
    }

    include!("auxiliary/vmlinux-legacy.rs");
}

// CHECK: Core reloc section #0 'uprobe/profile_views':
// CHECK: field_exists --> struct task_struct___modern.__state
// CHECK: field_exists --> struct task_struct___legacy.state
// CHECK-NOT: field_exists --> struct task_struct___legacy.pid
// CHECK: byte_off --> struct task_struct___legacy.pid
// CHECK-NOT: field_exists --> struct rq___legacy.clock
// CHECK: byte_off --> struct rq___legacy.clock
// CHECK-NOT: field_exists --> struct task_struct___modern.pid
// CHECK: byte_off --> struct task_struct___modern.pid
// CHECK-NOT: field_exists --> struct task_struct___modern.se.load.weight
// CHECK: byte_off --> struct task_struct___modern.se.load.weight
// CHECK-NOT: field_exists --> struct rq___modern.clock_task
// CHECK: byte_off --> struct rq___modern.clock_task

#[no_mangle]
#[link_section = "uprobe/profile_views"]
pub unsafe extern "C" fn profile_views(task: *const u8, rq: *const u8) -> u64 {
    if let Some(profile) = modern::Profile::detect() {
        let task = profile.view(unsafe { &*task.cast::<modern::task_struct>() });
        let rq = profile.view(unsafe { &*rq.cast::<modern::rq>() });
        return (task.pid().get() as *const i32 as usize)
            .wrapping_add(task.se().load().weight().get() as *const u64 as usize)
            .wrapping_add(rq.clock_task().get() as *const u64 as usize) as u64;
    }

    if let Some(profile) = legacy::Profile::detect() {
        let task = profile.view(unsafe { &*task.cast::<legacy::task_struct>() });
        let rq = profile.view(unsafe { &*rq.cast::<legacy::rq>() });
        return (task.pid().get() as *const i32 as usize)
            .wrapping_add(rq.clock().get() as *const u64 as usize) as u64;
    }

    0
}
