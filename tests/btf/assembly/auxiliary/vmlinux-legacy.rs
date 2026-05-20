#[btf(flavor = legacy)]
pub struct task_struct {
    pub state: u64,
    pub pid: i32,
}

#[btf(flavor = legacy)]
pub struct rq {
    pub clock: u64,
}
