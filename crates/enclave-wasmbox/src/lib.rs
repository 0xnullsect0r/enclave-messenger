//! A WebAssembly sandbox for Enclave's media process on iOS
//! (`docs/15-client.md` §1.3, milestone I2).
//!
//! iOS starts no processes, so the decoders can't be confined the way the
//! desktop confines `enclave-mediad` (its own process, seccomp, Landlock)
//! or Android does (an `isolatedProcess`). Instead mediad is built for
//! `wasm32-wasip1` and run here, in the wasmi interpreter (no JIT): a
//! parser bug can corrupt only the module's own linear memory, which is
//! capped, and the module can reach nothing but what is given to it.
//!
//! It gets the smallest WASI there is: standard input and output are the
//! vault's pipes, standard error is ours, the clocks are read-only; no
//! arguments, no environment, no files (no preopened folders; `path_open`
//! is refused), no sockets, no randomness.

use std::io::{Read, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wasmi::{
    Caller, Engine, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

/// The module's memory, at most: a 25-megapixel picture and its buffers.
pub const MEMORY_LIMIT: usize = 1 << 30;

/// WASI error numbers used here.
const SUCCESS: i32 = 0;
const EBADF: i32 = 8;
const EINVAL: i32 = 28;
const EIO: i32 = 29;
const ENOTCAPABLE: i32 = 76;

const WASI: &str = "wasi_snapshot_preview1";

/// Why the module couldn't run.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<wasmi::Error> for Error {
    fn from(e: wasmi::Error) -> Self {
        Self(e.to_string())
    }
}

struct Host {
    input: Box<dyn Read + Send>,
    output: Box<dyn Write + Send>,
    started: Instant,
    limits: StoreLimits,
}

fn memory(caller: &Caller<'_, Host>) -> Option<Memory> {
    caller.get_export("memory").and_then(Extern::into_memory)
}

fn put(caller: &mut Caller<'_, Host>, at: i32, bytes: &[u8]) -> bool {
    let Some(m) = memory(caller) else {
        return false;
    };
    u32::try_from(at).is_ok_and(|at| m.write(caller, at as usize, bytes).is_ok())
}

fn get(caller: &Caller<'_, Host>, at: i32, len: usize) -> Option<Vec<u8>> {
    let m = memory(caller)?;
    let mut buf = vec![0; len];
    m.read(caller, usize::try_from(at).ok()?, &mut buf).ok()?;
    Some(buf)
}

fn u32_at(caller: &Caller<'_, Host>, at: i32) -> Option<u32> {
    get(caller, at, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The `(pointer, length)` pairs of an iovec list.
fn iovecs(caller: &Caller<'_, Host>, at: i32, n: i32) -> Option<Vec<(i32, usize)>> {
    let n = usize::try_from(n).ok()?;
    if n > 1024 {
        return None;
    }
    (0..n)
        .map(|k| {
            let base = at.checked_add(i32::try_from(k * 8).ok()?)?;
            let ptr = u32_at(caller, base)?;
            let len = u32_at(caller, base.checked_add(4)?)?;
            Some((i32::try_from(ptr).ok()?, len as usize))
        })
        .collect()
}

fn link(linker: &mut Linker<Host>) -> Result<(), wasmi::Error> {
    // No arguments and no environment.
    for (sizes, values) in [
        ("args_sizes_get", "args_get"),
        ("environ_sizes_get", "environ_get"),
    ] {
        linker.func_wrap(
            WASI,
            sizes,
            |mut c: Caller<'_, Host>, count: i32, size: i32| -> i32 {
                if put(&mut c, count, &0u32.to_le_bytes()) && put(&mut c, size, &0u32.to_le_bytes())
                {
                    SUCCESS
                } else {
                    EINVAL
                }
            },
        )?;
        linker.func_wrap(WASI, values, |_: Caller<'_, Host>, _: i32, _: i32| -> i32 {
            SUCCESS
        })?;
    }
    linker.func_wrap(
        WASI,
        "clock_time_get",
        |mut c: Caller<'_, Host>, id: i32, _precision: i64, out: i32| -> i32 {
            let nanos = match id {
                0 => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                _ => c.data().started.elapsed().as_nanos(),
            };
            let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
            if put(&mut c, out, &nanos.to_le_bytes()) {
                SUCCESS
            } else {
                EINVAL
            }
        },
    )?;
    linker.func_wrap(WASI, "fd_close", |_: Caller<'_, Host>, _: i32| -> i32 {
        SUCCESS
    })?;
    linker.func_wrap(
        WASI,
        "fd_fdstat_get",
        |mut c: Caller<'_, Host>, fd: i32, out: i32| -> i32 {
            if !(0..=2).contains(&fd) {
                return EBADF;
            }
            // A character device, no flags, every right.
            let mut stat = [0u8; 24];
            stat[0] = 2;
            stat[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            stat[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
            if put(&mut c, out, &stat) {
                SUCCESS
            } else {
                EINVAL
            }
        },
    )?;
    // No preopened folders, so no files at all.
    linker.func_wrap(
        WASI,
        "fd_prestat_get",
        |_: Caller<'_, Host>, _: i32, _: i32| -> i32 { EBADF },
    )?;
    linker.func_wrap(
        WASI,
        "fd_prestat_dir_name",
        |_: Caller<'_, Host>, _: i32, _: i32, _: i32| -> i32 { EBADF },
    )?;
    linker.func_wrap(
        WASI,
        "path_open",
        |_: Caller<'_, Host>,
         _: i32,
         _: i32,
         _: i32,
         _: i32,
         _: i32,
         _: i64,
         _: i64,
         _: i32,
         _: i32|
         -> i32 { ENOTCAPABLE },
    )?;
    linker.func_wrap(
        WASI,
        "fd_read",
        |mut c: Caller<'_, Host>, fd: i32, iovs: i32, n: i32, out: i32| -> i32 {
            if fd != 0 {
                return EBADF;
            }
            let Some(iovs) = iovecs(&c, iovs, n) else {
                return EINVAL;
            };
            let mut total = 0usize;
            for (ptr, len) in iovs {
                let mut buf = vec![0; len.min(1 << 20)];
                let got = match c.data_mut().input.read(&mut buf) {
                    Ok(g) => g,
                    Err(_) => return EIO,
                };
                if !put(&mut c, ptr, &buf[..got]) {
                    return EINVAL;
                }
                total += got;
                if got < buf.len() {
                    break;
                }
            }
            let total = u32::try_from(total).unwrap_or(u32::MAX);
            if put(&mut c, out, &total.to_le_bytes()) {
                SUCCESS
            } else {
                EINVAL
            }
        },
    )?;
    linker.func_wrap(
        WASI,
        "fd_write",
        |mut c: Caller<'_, Host>, fd: i32, iovs: i32, n: i32, out: i32| -> i32 {
            if !(1..=2).contains(&fd) {
                return EBADF;
            }
            let Some(iovs) = iovecs(&c, iovs, n) else {
                return EINVAL;
            };
            let mut total = 0usize;
            for (ptr, len) in iovs {
                let Some(bytes) = get(&c, ptr, len) else {
                    return EINVAL;
                };
                let wrote = if fd == 1 {
                    let o = &mut c.data_mut().output;
                    o.write_all(&bytes).and_then(|()| o.flush())
                } else {
                    std::io::stderr().write_all(&bytes)
                };
                if wrote.is_err() {
                    return EIO;
                }
                total += len;
            }
            let total = u32::try_from(total).unwrap_or(u32::MAX);
            if put(&mut c, out, &total.to_le_bytes()) {
                SUCCESS
            } else {
                EINVAL
            }
        },
    )?;
    linker.func_wrap(
        WASI,
        "proc_exit",
        |_: Caller<'_, Host>, code: i32| -> Result<(), wasmi::Error> {
            Err(wasmi::Error::i32_exit(code))
        },
    )?;
    linker.func_wrap(WASI, "sched_yield", |_: Caller<'_, Host>| -> i32 {
        SUCCESS
    })?;
    Ok(())
}

/// Run the WASI program `module` with `input` as its standard input and
/// `output` as its standard output until it ends: its exit status.
pub fn run(
    module: &[u8],
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> Result<i32, Error> {
    let engine = Engine::default();
    let module = Module::new(&engine, module)?;
    let host = Host {
        input: Box::new(input),
        output: Box::new(output),
        started: Instant::now(),
        limits: StoreLimitsBuilder::new()
            .memory_size(MEMORY_LIMIT)
            .instances(1)
            .memories(1)
            .tables(1)
            .build(),
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|h| &mut h.limits);
    let mut linker = Linker::new(&engine);
    link(&mut linker)?;
    let instance = linker.instantiate_and_start(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&store, "_start")?;
    match start.call(&mut store, ()) {
        Ok(()) => Ok(0),
        Err(e) => match e.i32_exit_status() {
            Some(code) => Ok(code),
            None => Err(e.into()),
        },
    }
}
