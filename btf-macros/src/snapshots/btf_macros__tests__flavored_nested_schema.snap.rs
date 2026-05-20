#[allow(non_camel_case_types)]
pub struct task_struct;
#[doc(hidden)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct __BtfCarrierFortask_struct___modern {
    pid: <i32 as ::btf::BtfType>::Carrier,
    se: <sched_entity as ::btf::BtfType>::Carrier,
}
#[doc(hidden)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct __BtfFieldFortask_struct_0 {
    pid: u8,
}
#[doc(hidden)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct __BtfFieldFortask_struct_1 {
    se: u8,
}
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct __BtfViewFortask_struct<'__btf, __BtfRoot, __BtfPath, __BtfMode>
where
    __BtfRoot: ::btf::BtfType,
{
    field: ::btf::Field<'__btf, __BtfRoot, task_struct, __BtfPath, __BtfMode>,
}
impl ::btf::BtfType for task_struct {
    type Carrier = __BtfCarrierFortask_struct___modern;
    type View<'__btf, __BtfRoot, __BtfPath, __BtfMode> = __BtfViewFortask_struct<
        '__btf,
        __BtfRoot,
        __BtfPath,
        __BtfMode,
    >
    where
        Self: '__btf,
        __BtfRoot: ::btf::BtfType + '__btf;
    #[inline(always)]
    fn __btf_view<'__btf, __BtfRoot, __BtfPath, __BtfMode>(
        field: ::btf::Field<'__btf, __BtfRoot, Self, __BtfPath, __BtfMode>,
    ) -> Self::View<'__btf, __BtfRoot, __BtfPath, __BtfMode>
    where
        Self: '__btf,
        __BtfRoot: ::btf::BtfType + '__btf,
    {
        __BtfViewFortask_struct { field }
    }
}
unsafe impl ::btf::InModule<__BtfModule> for task_struct {}
impl<
    '__btf,
    __BtfRoot,
    __BtfPath,
    __BtfMode,
> __BtfViewFortask_struct<'__btf, __BtfRoot, __BtfPath, __BtfMode>
where
    __BtfRoot: ::btf::BtfType + '__btf,
{
    #[inline(always)]
    pub fn exists(&self) -> bool {
        self.field.exists()
    }
    #[inline(always)]
    pub fn pid(
        &self,
    ) -> <i32 as ::btf::BtfType>::View<
        '__btf,
        __BtfRoot,
        ::btf::FieldPath<__BtfPath, __BtfFieldFortask_struct_0>,
        __BtfMode,
    > {
        let field = self.field.__btf_field::<i32, __BtfFieldFortask_struct_0>();
        <i32 as ::btf::BtfType>::__btf_view(field)
    }
    #[inline(always)]
    pub fn se(
        &self,
    ) -> <sched_entity as ::btf::BtfType>::View<
        '__btf,
        __BtfRoot,
        ::btf::FieldPath<__BtfPath, __BtfFieldFortask_struct_1>,
        __BtfMode,
    > {
        let field = self.field.__btf_field::<sched_entity, __BtfFieldFortask_struct_1>();
        <sched_entity as ::btf::BtfType>::__btf_view(field)
    }
}
impl task_struct {
    #[inline(always)]
    pub fn pid<'__btf>(
        &'__btf self,
    ) -> <i32 as ::btf::BtfType>::View<
        '__btf,
        Self,
        ::btf::FieldPath<::btf::RootPath, __BtfFieldFortask_struct_0>,
        ::btf::Optional,
    > {
        let root = ::btf::Field::__btf_root(self);
        let field = root.__btf_field::<i32, __BtfFieldFortask_struct_0>();
        <i32 as ::btf::BtfType>::__btf_view(field)
    }
    #[inline(always)]
    pub fn se<'__btf>(
        &'__btf self,
    ) -> <sched_entity as ::btf::BtfType>::View<
        '__btf,
        Self,
        ::btf::FieldPath<::btf::RootPath, __BtfFieldFortask_struct_1>,
        ::btf::Optional,
    > {
        let root = ::btf::Field::__btf_root(self);
        let field = root.__btf_field::<sched_entity, __BtfFieldFortask_struct_1>();
        <sched_entity as ::btf::BtfType>::__btf_view(field)
    }
    /// Starts a query-only root used by `btf_profile!` discriminators.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __btf_probe() -> __BtfViewFortask_struct<
        'static,
        Self,
        ::btf::RootPath,
        ::btf::Probe,
    > {
        let root = ::btf::Field::<
            Self,
            Self,
            ::btf::RootPath,
            ::btf::Probe,
        >::__btf_probe();
        <Self as ::btf::BtfType>::__btf_view(root)
    }
}
