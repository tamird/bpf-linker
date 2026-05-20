# CO-RE field access protocol

This prototype demonstrates a Rust API for CO-RE field access and
feature-detection profiles. Its output is not a new format: `bpf-linker`
emits ordinary `.BTF` and `.BTF.ext` field-info relocations consumable by
existing loaders such as libbpf.

## API

A program declares only the kernel fields it inspects:

```rust
#[btf]
struct load_weight {
    weight: u64,
}

#[btf]
struct sched_entity {
    load: load_weight,
}

#[btf]
struct task_struct {
    pid: i32,
    se: sched_entity,
}

let pid: Option<&i32> = task.pid().get();
let weight: Option<&u64> = task.se().load().weight().get();
```

These declarations are schemas, not Rust representations of complete kernel
objects. Missing fields and incorrect local offsets are expected: the loader
matches each declared path against target-kernel BTF.

Intermediate methods build a path; they do not access memory. Thus
`task.se().load().weight().get()` produces one optional access to the complete
`task_struct.se.load.weight` path. Aggregate views expose further field
methods and `exists()`, but not `get()`: a schema ZST is not aggregate kernel
data that can usefully be returned by reference.

Each generated bindings module can select its coherent layout with a field
discriminator:

```rust
mod modern {
    btf_profile! {
        pub struct Profile {
            detect { task_struct.__state }
        }
    }

    #[btf(flavor = modern)]
    struct task_struct { __state: u32, pid: i32 }

    #[btf(flavor = modern)]
    struct rq { clock_task: u64 }
}

if let Some(profile) = modern::Profile::detect() {
    let task = profile.view(task);
    let rq = profile.view(rq);
    let pid: &i32 = task.pid().get();
    let clock: &u64 = rq.clock_task().get();
}
```

Success selects the whole `modern` module. This matters for generated
bindings: a separate `vmlinux.rs` module can describe each kernel layout,
without maintaining a second list of all types certified by its
discriminator. Thus a discriminator in `task_struct` can justify an access
through an unrelated `rq` from the same selected module.

## Generated Bindings Shape

The expected input is one generated schema module per kernel layout. In an
eBPF crate, a checked-in or build-generated wrapper can provide the profile
selection and include the generated schemas:

```rust
use btf::Profile as _;

mod v6_8 {
    use btf_macros::{btf, btf_profile};

    btf_profile! {
        pub struct Profile {
            detect { task_struct.__state }
        }
    }

    include!(concat!(env!("OUT_DIR"), "/vmlinux/v6_8.rs"));
}

mod v5_10 {
    use btf_macros::{btf, btf_profile};

    btf_profile! {
        pub struct Profile {
            detect { task_struct.state }
        }
    }

    include!(concat!(env!("OUT_DIR"), "/vmlinux/v5_10.rs"));
}
```

The included `v6_8.rs` contains the schema slice needed by the program,
including intermediate nested structs and unrelated root types:

```rust
#[btf(flavor = v6_8)]
pub struct task_struct {
    pub __state: u32,     // discriminator
    pub pid: i32,         // accessed leaf
    pub se: sched_entity, // intermediate path component
}

#[btf(flavor = v6_8)]
pub struct sched_entity {
    pub load: load_weight,
}

#[btf(flavor = v6_8)]
pub struct load_weight {
    pub weight: u64,
}

#[btf(flavor = v6_8)]
pub struct rq {
    pub clock_task: u64, // unrelated root justified by the module witness
}
```

The required macro invocations are therefore:

1. Exactly one `btf_profile!` in each versioned wrapper module. Its
   discriminators establish when that complete bindings module applies.
2. One `#[btf(flavor = module_flavor)]` on every generated schema struct in
   that module: roots, nested path components, and unrelated roots accessed
   after selection.
3. No per-field or per-use invocation in the BPF program. It calls
   `Profile::detect()` and then `profile.view(&value)` for objects belonging
   to the selected module.

Profiles are tried as an ordered decision tree. If an old discriminator also
exists in newer kernels, test the newer profile first and use the older
profile as its fallback, as the `modern` / `legacy` fixture does.

Generating a complete raw bindgen dump and decorating every item is not yet
the contract of this prototype. `#[btf]` currently handles named struct
schemas whose retained member types have `BtfType` support. A practical
generator starts from all accessed and discriminator paths, takes their
transitive struct/member closure for each target BTF, and emits that partial
`vmlinux.rs` schema slice. Support for raw bindgen unions, anonymous carrier
types, and other complete-dump details can be added separately.

There are two straightforward generator implementation choices. Bindgen
0.72 exposes `ParseCallbacks::add_attributes`, which can inject the
`#[btf(flavor = ...)]` annotation. A generator that already parses bindgen
output into a `syn::File` can instead retain selected members and add the
annotation during that post-processing pass before writing each `vmlinux.rs`.

## Temporary Protocol

Rust does not yet provide the full-path BTF field-info intrinsic needed by
this API. The prototype transports the path to `bpf-linker` through debug
information:

1. `#[btf]` replaces each schema with a public ZST address view and a hidden
   carrier struct. The carrier contains the declared members and supplies the
   local BTF graph.
2. Each declared member also gets a one-member marker struct. The generated
   identifier only makes the Rust type unique; the marker's member name is
   the field name consumed by the linker.
3. Getter chaining forms a type-level path:

```rust
FieldPath<
    FieldPath<
        FieldPath<RootPath, marker_for_task_struct_se>,
        marker_for_sched_entity_load>,
    marker_for_load_weight_weight>,
>
```

4. A terminal query calls an undefined inline polyfill:

```text
__btf_field_exists
__btf_field_byte_offset
```

The call takes a `Root::Carrier` pointer and a null pointer of the path type.
Opaque LLVM pointers lose those source types, but the inlined helper's debug
signature retains them.

5. `FieldRelocPass` reads the carrier and path types from debug information,
   recovers field names from the marker members, maps them to local carrier
   indices, restores carrier names to the BTF schema names, and emits:

```text
llvm.preserve.struct.access.index ... chain
llvm.bpf.preserve.field.info
```

For `task.se().load().weight()`, the local access string is `0:1:0:0` for the
schema shown above. The resulting CO-RE record names
`struct task_struct.se.load.weight` in the same form a standard loader
already understands.

Ordinary `get()` emits `field_exists` followed by `byte_off`, returning
`Option<&Value>`. A profile-backed `get()` emits only `byte_off`; it must be
dominated by the discriminator branch that created its proof token. A false
profile promise causes an unsupported relocation in the selected branch, not
a valid required access.

`btf_profile!` also defines a hidden marker in its enclosing bindings module.
Each flavored `#[btf]` schema there implements membership in that marker, so a
successful witness enables required views for every schema in the selected
module. Flavored carrier names ending in suffixes such as `___modern` let
CO-RE retain distinct local graphs while matching the target type name.

## Compiler Endpoint

The temporary linker protocol exists only because the available proposed
intrinsics describe a single member. Deferred views require a terminal
operation over a complete path:

```rust
btf_field_exists::<Root>(path)
btf_field_byte_offset::<Root>(path)
```

where `path` is a compile-time sequence such as `[se, load, weight]`.
With such compiler support, the user API remains unchanged while:

- marker structs and `FieldPath` cease to be a debug-information message;
- the undefined polyfills disappear; and
- `FieldRelocPass` disappears or shrinks to any naming bridge still required
  for ZST schemas.

## Scope

This prototype does not make normal Rust field projection relocatable or
define a loader extension. It demonstrates:

- optional full-path field access from partial schemas;
- module witnesses that remove `Option` after a discriminator selects one
  versioned bindings module, including access through unrelated root types;
- standard CO-RE relocation output suitable for existing loaders.

The implementation and executable evidence are in:

- [`btf-macros/src/lib.rs`](btf-macros/src/lib.rs)
- [`btf/src/lib.rs`](btf/src/lib.rs)
- [`src/llvm/field_reloc.rs`](src/llvm/field_reloc.rs)
- [`tests/btf/assembly/task-struct-getters.rs`](tests/btf/assembly/task-struct-getters.rs)
- [`tests/btf/assembly/profile-views.rs`](tests/btf/assembly/profile-views.rs)
