// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

pub use cose_rs;

// `cnap-ffi` sets `[lib] name = "cnap"` so that C consumers link `libcnap.a`, hence
// the crate is named `cnap` here rather than `cnap_ffi`. Re-exporting it is what
// forces its `#[no_mangle] extern "C"` entry points to be retained in the staticlib;
// without a reference the linker would drop the whole crate as unused.
pub use cnap;
