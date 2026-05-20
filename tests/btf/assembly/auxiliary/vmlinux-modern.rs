// Representative generated schema slice for one vmlinux flavor. The
// generator emits `#[btf]` on each retained struct, including unrelated root
// types made available by this module's `Profile`.
#[btf(flavor = modern)]
pub struct task_struct {
    pub __state: u32,
    pub pid: i32,
    pub se: sched_entity,
}

#[btf(flavor = modern)]
pub struct sched_entity {
    pub load: load_weight,
}

#[btf(flavor = modern)]
pub struct load_weight {
    pub weight: u64,
}

#[btf(flavor = modern)]
pub struct rq {
    pub clock_task: u64,
}
