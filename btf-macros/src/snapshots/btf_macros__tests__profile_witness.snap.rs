#[doc(hidden)]
pub struct __BtfModule;
#[derive(Clone, Copy)]
pub struct Profile {
    _private: ::btf::ProfileToken,
}
impl ::btf::Profile for Profile {
    type Module = __BtfModule;
}
impl Profile {
    #[inline(always)]
    pub fn detect() -> ::core::option::Option<Self> {
        if true && <task_struct>::__btf_probe().__state().exists() {
            ::core::option::Option::Some(Self {
                _private: unsafe { ::btf::__btf_profile_token() },
            })
        } else {
            ::core::option::Option::None
        }
    }
}
