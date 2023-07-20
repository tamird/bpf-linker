mod di;
mod iter;
mod types;

use std::{
    borrow::Cow,
    collections::HashSet,
    ffi::{c_uchar, c_void, CStr, CString},
    os::raw::c_char,
    ptr, slice, str,
};

pub use di::DISanitizer;
use iter::{
    IterInstructions as _, IterBasicBlocks as _, IterModuleFunctions as _,
    IterModuleGlobalAliases as _, IterModuleGlobals as _,
};
use libc::c_char as libc_char;
use llvm_sys::{
    bit_reader::LLVMParseBitcodeInContext2,
    core::{
        LLVMBuildCall2, LLVMBuildIntCast2, LLVMCountParamTypes, LLVMCreateBuilderInContext,
        LLVMCreateMemoryBufferWithMemoryRange, LLVMDisposeBuilder, LLVMDisposeMemoryBuffer,
        LLVMDisposeMessage, LLVMGetDiagInfoDescription, LLVMGetDiagInfoSeverity,
        LLVMGetMDString,
        LLVMGetEnumAttributeKindForName, LLVMGetModuleContext, LLVMGetModuleInlineAsm,
        LLVMGetNamedFunction, LLVMGetNumOperands, LLVMGetOperand, LLVMGetParamTypes, LLVMGetTarget,
        LLVMGetValueName2, LLVMGlobalGetValueType, LLVMInstructionEraseFromParent,
        LLVMIsAMemCpyInst, LLVMIsAMemIntrinsic, LLVMIsAMemMoveInst, LLVMIsAMemSetInst,
        LLVMModuleCreateWithNameInContext, LLVMPositionBuilderBefore, LLVMPrintModuleToFile,
        LLVMRemoveEnumAttributeAtIndex, LLVMReplaceAllUsesWith, LLVMSetLinkage,
        LLVMSetModuleInlineAsm2, LLVMSetVisibility, LLVMTypeOf,
    },
    debuginfo::LLVMStripModuleDebugInfo,
    error::{
        LLVMDisposeErrorMessage, LLVMGetErrorMessage, LLVMGetErrorTypeId, LLVMGetStringErrorTypeId,
    },
    linker::LLVMLinkModules2,
    object::{
        LLVMCreateBinary, LLVMDisposeBinary, LLVMDisposeSectionIterator, LLVMGetSectionContents,
        LLVMGetSectionName, LLVMGetSectionSize, LLVMMoveToNextSection,
        LLVMObjectFileCopySectionIterator, LLVMObjectFileIsSectionIteratorAtEnd,
    },
    prelude::{LLVMContextRef, LLVMDiagnosticInfoRef, LLVMModuleRef, LLVMValueRef},
    support::LLVMParseCommandLineOptions,
    target::{
        LLVMInitializeBPFAsmParser, LLVMInitializeBPFAsmPrinter, LLVMInitializeBPFDisassembler,
        LLVMInitializeBPFTarget, LLVMInitializeBPFTargetInfo, LLVMInitializeBPFTargetMC,
    },
    target_machine::{
        LLVMCodeGenFileType, LLVMCodeGenOptLevel, LLVMCodeModel, LLVMCreateTargetMachine,
        LLVMGetTargetFromTriple, LLVMRelocMode, LLVMTargetMachineEmitToFile, LLVMTargetMachineRef,
        LLVMTargetRef,
    },
    transforms::pass_builder::{
        LLVMCreatePassBuilderOptions, LLVMDisposePassBuilderOptions, LLVMRunPasses,
    },
    LLVMAttributeFunctionIndex, LLVMLinkage, LLVMVisibility,
};
use tracing::{debug, error};

use crate::OptLevel;

pub unsafe fn init<T: AsRef<str>>(args: &[T], overview: &str) {
    LLVMInitializeBPFTarget();
    LLVMInitializeBPFTargetMC();
    LLVMInitializeBPFTargetInfo();
    LLVMInitializeBPFAsmPrinter();
    LLVMInitializeBPFAsmParser();
    LLVMInitializeBPFDisassembler();

    parse_command_line_options(args, overview);
}

unsafe fn parse_command_line_options<T: AsRef<str>>(args: &[T], overview: &str) {
    let c_args = args
        .iter()
        .map(|s| CString::new(s.as_ref()).unwrap())
        .collect::<Vec<_>>();
    let c_ptrs = c_args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    let overview = CString::new(overview).unwrap();
    LLVMParseCommandLineOptions(c_ptrs.len() as i32, c_ptrs.as_ptr(), overview.as_ptr());
}

pub unsafe fn create_module(name: &str, context: LLVMContextRef) -> Option<LLVMModuleRef> {
    let c_name = CString::new(name).unwrap();
    let module = LLVMModuleCreateWithNameInContext(c_name.as_ptr(), context);

    if module.is_null() {
        return None;
    }

    Some(module)
}

pub unsafe fn find_embedded_bitcode(
    context: LLVMContextRef,
    data: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let buffer_name = CString::new("mem_buffer").unwrap();
    let buffer = LLVMCreateMemoryBufferWithMemoryRange(
        data.as_ptr() as *const libc_char,
        data.len(),
        buffer_name.as_ptr(),
        0,
    );

    let (bin, message) = Message::with(|message| LLVMCreateBinary(buffer, context, message));
    if bin.is_null() {
        return Err(message.as_c_str().unwrap().to_str().unwrap().to_string());
    }

    let mut ret = None;
    let iter = LLVMObjectFileCopySectionIterator(bin);
    while LLVMObjectFileIsSectionIteratorAtEnd(bin, iter) == 0 {
        let name = LLVMGetSectionName(iter);
        if !name.is_null() {
            let name = CStr::from_ptr(name);
            if name.to_str().unwrap() == ".llvmbc" {
                let buf = LLVMGetSectionContents(iter);
                let size = LLVMGetSectionSize(iter) as usize;
                ret = Some(slice::from_raw_parts(buf as *const c_uchar, size).to_vec());
                break;
            }
        }
        LLVMMoveToNextSection(iter);
    }
    LLVMDisposeSectionIterator(iter);
    LLVMDisposeBinary(bin);
    LLVMDisposeMemoryBuffer(buffer);

    Ok(ret)
}

#[must_use]
pub unsafe fn link_bitcode_buffer(
    context: LLVMContextRef,
    module: LLVMModuleRef,
    buffer: &[u8],
) -> bool {
    let mut linked = false;
    let buffer_name = CString::new("mem_buffer").unwrap();
    let buffer = LLVMCreateMemoryBufferWithMemoryRange(
        buffer.as_ptr() as *const libc_char,
        buffer.len(),
        buffer_name.as_ptr(),
        0,
    );

    let mut temp_module = ptr::null_mut();

    if LLVMParseBitcodeInContext2(context, buffer, &mut temp_module) == 0 {
        linked = LLVMLinkModules2(module, temp_module) == 0;
    }

    LLVMDisposeMemoryBuffer(buffer);

    linked
}

pub unsafe fn target_from_triple(triple: &CStr) -> Result<LLVMTargetRef, String> {
    let mut target = ptr::null_mut();
    let (ret, message) =
        Message::with(|message| LLVMGetTargetFromTriple(triple.as_ptr(), &mut target, message));
    if ret == 0 {
        Ok(target)
    } else {
        Err(message.as_c_str().unwrap().to_str().unwrap().to_string())
    }
}

pub unsafe fn target_from_module(module: LLVMModuleRef) -> Result<LLVMTargetRef, String> {
    let triple = LLVMGetTarget(module);
    target_from_triple(CStr::from_ptr(triple))
}

pub unsafe fn create_target_machine(
    target: LLVMTargetRef,
    triple: &str,
    cpu: &str,
    features: &str,
) -> Option<LLVMTargetMachineRef> {
    let triple = CString::new(triple).unwrap();
    let cpu = CString::new(cpu).unwrap();
    let features = CString::new(features).unwrap();
    let tm = LLVMCreateTargetMachine(
        target,
        triple.as_ptr(),
        cpu.as_ptr(),
        features.as_ptr(),
        LLVMCodeGenOptLevel::LLVMCodeGenLevelAggressive,
        LLVMRelocMode::LLVMRelocDefault,
        LLVMCodeModel::LLVMCodeModelDefault,
    );
    if tm.is_null() {
        None
    } else {
        Some(tm)
    }
}

pub unsafe fn optimize(
    tm: LLVMTargetMachineRef,
    module: LLVMModuleRef,
    opt_level: OptLevel,
    ignore_inline_never: bool,
    export_symbols: &HashSet<Cow<'static, str>>,
) -> Result<(), String> {
    if module_asm_is_probestack(module) {
        LLVMSetModuleInlineAsm2(module, ptr::null_mut(), 0);
    }

    for sym in module.globals_iter() {
        internalize(sym, symbol_name(sym), export_symbols);
    }
    for sym in module.global_aliases_iter() {
        internalize(sym, symbol_name(sym), export_symbols);
    }

    for function in module.functions_iter() {
        let name = symbol_name(function);
        if !name.starts_with("llvm.") {
            if ignore_inline_never {
                remove_attribute(function, "noinline");
            }
            internalize(function, name, export_symbols);
        }
    }

    let passes = [
        // NB: "default<_>" must be the first pass in the list, otherwise it will be ignored.
        match opt_level {
            // Pretty much nothing compiles with -O0 so make it an alias for -O1.
            OptLevel::No | OptLevel::Less => "default<O1>",
            OptLevel::Default => "default<O2>",
            OptLevel::Aggressive => "default<O3>",
            OptLevel::Size => "default<Os>",
            OptLevel::SizeMin => "default<Oz>",
        },
        // NB: This seems to be included in most default pipelines, but not obviously all of them.
        // See
        // https://github.com/llvm/llvm-project/blob/bbe2887f/llvm/lib/Passes/PassBuilderPipelines.cpp#L2011-L2012
        // for a case which includes DCE only conditionally. Better safe than sorry; include it always.
        "dce",
    ];

    let passes = passes.join(",");
    debug!("running passes: {passes}");
    let passes = CString::new(passes).unwrap();
    let options = LLVMCreatePassBuilderOptions();
    let error = LLVMRunPasses(module, passes.as_ptr(), tm, options);
    LLVMDisposePassBuilderOptions(options);
    // Handle the error and print it to stderr.
    if !error.is_null() {
        let error_type_id = LLVMGetErrorTypeId(error);
        // This is the only error type that exists currently, but there might be more in the future.
        assert_eq!(error_type_id, LLVMGetStringErrorTypeId());
        let error_message = LLVMGetErrorMessage(error);
        let error_string = CStr::from_ptr(error_message).to_str().unwrap().to_owned();
        LLVMDisposeErrorMessage(error_message);
        return Err(error_string);
    }


    // Collect up all the memory intrinsics. We're going to replace these with
    // calls to the equivalent functions, but we can't remove the instructions
    // until we're done iterating over them.
    let mut mem_intrinsic_instructions = Vec::new();
    for function in module.functions_iter() {
        for basic_block in function.basic_blocks_iter() {
            for instruction in basic_block.instructions_iter() {
                let instruction = LLVMIsAMemIntrinsic(instruction);
                if instruction.is_null() {
                    continue;
                }
                mem_intrinsic_instructions.push(instruction);
            }
        }
    }

    // Replace the memory intrinsics with calls to the equivalent functions. This works around a
    // check added in https://github.com/llvm/llvm-project/commit/e4975487 that causes LLVM to emit
    // fatal errors on calls to external functions. In particular, we often end up with memset
    // intrinsics that LLVM lowers to calls - which are fine because we provide implementations but
    // - which trip this check. We rewrite these intrinsics as internal calls and everyone is happy.
    //
    // TODO: remove this when https://reviews.llvm.org/D155894 is resolved and the check is removed.
    {
        // LLVMGet* functions do not pass ownership to the caller.
        let context = LLVMGetModuleContext(module);

        let builder = LLVMCreateBuilderInContext(context);
        for instruction in mem_intrinsic_instructions.iter().copied() {
            let instruction_num_operands = LLVMGetNumOperands(instruction);
            let instruction_num_operands: u32 = instruction_num_operands.try_into().unwrap();
            let mut instruction_operands: Vec<_> = (0..instruction_num_operands)
                .map(|i| LLVMGetOperand(instruction, i))
                .collect();

            let instruction_name = if !LLVMIsAMemCpyInst(instruction).is_null() {
                "memcpy"
            } else if !LLVMIsAMemMoveInst(instruction).is_null() {
                "memmove"
            } else if !LLVMIsAMemSetInst(instruction).is_null() {
                "memset"
            } else {
                panic!("unknown mem intrinsic");
            };
            let function = {
                let instruction_name = CString::new(instruction_name).unwrap();
                LLVMGetNamedFunction(module, instruction_name.as_ptr())
            };
            // The user neglected to defined a required intrinsic. Perhaps we
            // should return an error instead of panicking.
            assert!(
                !function.is_null(),
                "missing mem intrinsic function {instruction_name}"
            );
            let function_type = LLVMGlobalGetValueType(function);
            let param_count = LLVMCountParamTypes(function_type);

            // Call instructions can't have a name; attempting to set one crashes LLVM.
            let empty_string = [0];

            LLVMPositionBuilderBefore(builder, instruction);
            let mut types = vec![ptr::null_mut(); param_count.try_into().unwrap()];
            LLVMGetParamTypes(function_type, types.as_mut_ptr());
            for (operand, param_type) in instruction_operands.iter_mut().zip(types.into_iter()) {
                let operand_type = LLVMTypeOf(*operand);
                if operand_type == param_type {
                    continue;
                }
                *operand = LLVMBuildIntCast2(
                    builder,
                    *operand,
                    param_type,
                    0, /* IsSigned */
                    empty_string.as_ptr(),
                );
            }

            let call = LLVMBuildCall2(
                builder,
                function_type,
                function,
                instruction_operands.as_mut_ptr(),
                param_count,
                empty_string.as_ptr(),
            );
            LLVMReplaceAllUsesWith(instruction, call);
            LLVMInstructionEraseFromParent(instruction);
        }
        LLVMDisposeBuilder(builder);
    }

    Ok(())
}

/// strips debug information, returns true if DI got stripped
pub unsafe fn strip_debug_info(module: LLVMModuleRef) -> bool {
    LLVMStripModuleDebugInfo(module) != 0
}

unsafe fn module_asm_is_probestack(module: LLVMModuleRef) -> bool {
    let mut len = 0;
    let ptr = LLVMGetModuleInlineAsm(module, &mut len);
    if ptr.is_null() {
        return false;
    }

    let asm = String::from_utf8_lossy(slice::from_raw_parts(ptr as *const c_uchar, len));
    asm.contains("__rust_probestack")
}

fn symbol_name<'a>(value: *mut llvm_sys::LLVMValue) -> &'a str {
    let mut name_len = 0;
    let ptr = unsafe { LLVMGetValueName2(value, &mut name_len) };
    unsafe { str::from_utf8(slice::from_raw_parts(ptr as *const c_uchar, name_len)).unwrap() }
}

unsafe fn remove_attribute(function: *mut llvm_sys::LLVMValue, name: &str) {
    let attr_kind = LLVMGetEnumAttributeKindForName(name.as_ptr() as *const c_char, name.len());
    LLVMRemoveEnumAttributeAtIndex(function, LLVMAttributeFunctionIndex, attr_kind);
}

pub unsafe fn write_ir(module: LLVMModuleRef, output: &CStr) -> Result<(), String> {
    let (ret, message) =
        Message::with(|message| LLVMPrintModuleToFile(module, output.as_ptr(), message));
    if ret == 0 {
        Ok(())
    } else {
        Err(message.as_c_str().unwrap().to_str().unwrap().to_string())
    }
}

pub unsafe fn codegen(
    tm: LLVMTargetMachineRef,
    module: LLVMModuleRef,
    output: &CStr,
    output_type: LLVMCodeGenFileType,
) -> Result<(), String> {
    let (ret, message) = Message::with(|message| {
        LLVMTargetMachineEmitToFile(tm, module, output.as_ptr() as *mut _, output_type, message)
    });
    if ret == 0 {
        Ok(())
    } else {
        Err(message.as_c_str().unwrap().to_str().unwrap().to_string())
    }
}

pub unsafe fn internalize(
    value: LLVMValueRef,
    name: &str,
    export_symbols: &HashSet<Cow<'static, str>>,
) {
    if !name.starts_with("llvm.") && !export_symbols.contains(name) {
        LLVMSetLinkage(value, LLVMLinkage::LLVMInternalLinkage);
        LLVMSetVisibility(value, LLVMVisibility::LLVMDefaultVisibility);
    }
}

pub trait LLVMDiagnosticHandler {
    fn handle_diagnostic(&mut self, severity: llvm_sys::LLVMDiagnosticSeverity, message: &str);
}

pub extern "C" fn diagnostic_handler<T: LLVMDiagnosticHandler>(
    info: LLVMDiagnosticInfoRef,
    handler: *mut c_void,
) {
    let severity = unsafe { LLVMGetDiagInfoSeverity(info) };
    let message = Message {
        ptr: unsafe { LLVMGetDiagInfoDescription(info) },
    };
    let handler = handler as *mut T;
    unsafe { &mut *handler }
        .handle_diagnostic(severity, message.as_c_str().unwrap().to_str().unwrap());
}

pub extern "C" fn fatal_error(reason: *const c_char) {
    error!("fatal error: {:?}", unsafe { CStr::from_ptr(reason) })
}

struct Message {
    ptr: *mut c_char,
}

impl Message {
    fn with<T, F: FnOnce(*mut *mut c_char) -> T>(f: F) -> (T, Self) {
        let mut ptr = ptr::null_mut();
        let t = f(&mut ptr);
        (t, Self { ptr })
    }

    fn as_c_str(&self) -> Option<&CStr> {
        let Self { ptr } = self;
        let ptr = *ptr;
        (!ptr.is_null()).then(|| unsafe { CStr::from_ptr(ptr) })
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        let Self { ptr } = self;
        let ptr = *ptr;
        if !ptr.is_null() {
            unsafe {
                LLVMDisposeMessage(ptr);
            }
        }
    }
}

fn mdstring_to_str<'a>(mdstring: LLVMValueRef) -> &'a str {
    let mut len = 0;
    let ptr = unsafe { LLVMGetMDString(mdstring, &mut len) };
    unsafe { str::from_utf8(slice::from_raw_parts(ptr as *const c_uchar, len as usize)).unwrap() }
}
