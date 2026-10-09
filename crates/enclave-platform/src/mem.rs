//! Locked memory for long-term secrets (`docs/02-cryptography.md` §12).
//!
//! Secret key bytes live in pages that are `mlock`ed (`VirtualLock` on
//! Windows), so they are never written to swap, and marked to stay out of
//! core dumps on Linux. Small secrets share pages: an arena hands out
//! power-of-two slots (32 B to one page) from locked pages, and a page is
//! unlocked and freed only when its last slot goes (one empty page per slot
//! size is kept, so short-lived keys don't lock and unlock a page each
//! time). Larger secrets get pages of their own. Every slot is zeroized
//! when freed.
//!
//! Locking is best effort: if the OS refuses (a `RLIMIT_MEMLOCK` too low,
//! say), the memory is still used and zeroized, and [`stats`] counts the
//! refusal.

use std::alloc::Layout;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

const MIN_SLOT: usize = 32;

static LOCKED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

/// Locked memory in use, and lock refusals so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Bytes in locked pages.
    pub locked_bytes: u64,
    /// Times the OS refused to lock a page.
    pub lock_failures: u64,
}

/// Locked memory in use.
pub fn stats() -> Stats {
    Stats {
        locked_bytes: LOCKED.load(Ordering::Relaxed),
        lock_failures: FAILED.load(Ordering::Relaxed),
    }
}

/// The OS page size.
pub fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        os::page_size()
            .filter(|p| p.is_power_of_two())
            .unwrap_or(4096)
    })
}

struct Page {
    base: usize,
    slot: usize,
    used: Vec<bool>,
    in_use: usize,
    locked: bool,
}

static ARENA: Mutex<Vec<Page>> = Mutex::new(Vec::new());

fn arena() -> std::sync::MutexGuard<'static, Vec<Page>> {
    // A panic while holding the lock leaves the arena consistent (every
    // change is one assignment), so a poisoned lock is still usable.
    ARENA.lock().unwrap_or_else(|e| e.into_inner())
}

fn page_layout(len: usize) -> Option<Layout> {
    let p = page_size();
    Layout::from_size_align(len.div_ceil(p).max(1) * p, p).ok()
}

/// Allocate `len` zeroed, page-aligned bytes and lock them.
fn new_pages(len: usize) -> Option<(NonNull<u8>, bool)> {
    let layout = page_layout(len)?;
    // SAFETY: the layout has a non-zero size (at least one page).
    let ptr = NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) })?;
    let locked = os::lock(ptr.as_ptr(), layout.size());
    if locked {
        LOCKED.fetch_add(layout.size() as u64, Ordering::Relaxed);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    Some((ptr, locked))
}

/// Unlock and free what [`new_pages`] gave for `len`.
fn free_pages(ptr: *mut u8, len: usize, locked: bool) {
    let Some(layout) = page_layout(len) else {
        return;
    };
    if locked {
        os::unlock(ptr, layout.size());
        LOCKED.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    }
    // SAFETY: `ptr` came from `alloc_zeroed` with this same layout and is
    // freed once (its owner is being dropped).
    unsafe { std::alloc::dealloc(ptr, layout) }
}

fn slot_for(len: usize) -> usize {
    len.max(MIN_SLOT).next_power_of_two()
}

/// `len` zeroed bytes, and (for a secret of its own pages) whether they
/// are locked.
fn alloc(len: usize) -> Option<(NonNull<u8>, bool)> {
    let slot = slot_for(len);
    if slot > page_size() {
        return new_pages(len);
    }
    let mut pages = arena();
    if let Some(page) = pages
        .iter_mut()
        .find(|p| p.slot == slot && p.in_use < p.used.len())
        && let Some(i) = page.used.iter().position(|u| !u)
    {
        page.used[i] = true;
        page.in_use += 1;
        return NonNull::new((page.base + i * slot) as *mut u8).map(|p| (p, false));
    }
    let (ptr, locked) = new_pages(page_size())?;
    let mut used = vec![false; page_size() / slot];
    used[0] = true;
    pages.push(Page {
        base: ptr.as_ptr() as usize,
        slot,
        used,
        in_use: 1,
        locked,
    });
    Some((ptr, false))
}

/// Zeroize and give back `len` bytes at `ptr` from [`alloc`] (`locked`
/// as it returned).
fn free(ptr: NonNull<u8>, len: usize, locked: bool) {
    let slot = slot_for(len);
    let large = slot > page_size();
    // SAFETY: `ptr` points to a whole slot (or, for a large secret, at
    // least `len` bytes) owned by the dropped secret; nothing else refers
    // to them.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), if large { len } else { slot }) };
    bytes.zeroize();
    if large {
        free_pages(ptr.as_ptr(), len, locked);
        return;
    }
    let mut pages = arena();
    let addr = ptr.as_ptr() as usize;
    let p = page_size();
    let Some(at) = pages
        .iter()
        .position(|pg| pg.slot == slot && (pg.base..pg.base + p).contains(&addr))
    else {
        return;
    };
    let page = &mut pages[at];
    let i = (addr - page.base) / slot;
    if page.used[i] {
        page.used[i] = false;
        page.in_use -= 1;
    }
    let empty = page.in_use == 0;
    let others = pages.iter().filter(|pg| pg.slot == slot).count() > 1;
    if empty && others {
        let page = pages.swap_remove(at);
        free_pages(page.base as *mut u8, p, page.locked);
    }
}

/// Secret bytes of any length in locked memory, zeroized when dropped.
pub struct SecretBytes {
    ptr: NonNull<u8>,
    len: usize,
    /// For a secret with pages of its own: whether they are locked.
    locked: bool,
}

// SAFETY: `SecretBytes` owns its allocation exclusively, like a `Box<[u8]>`.
unsafe impl Send for SecretBytes {}
// SAFETY: shared access is read-only through `&[u8]`.
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// `len` zero bytes.
    pub fn zeroed(len: usize) -> Self {
        let (ptr, locked) = alloc(len)
            .unwrap_or_else(|| std::alloc::handle_alloc_error(Layout::new::<[u8; MIN_SLOT]>()));
        Self { ptr, len, locked }
    }

    /// A copy of `b`.
    pub fn from_slice(b: &[u8]) -> Self {
        let mut s = Self::zeroed(b.len());
        s.copy_from_slice(b);
        s
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` points to at least `len` initialized bytes we own.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `deref`, and `&mut self` makes the access unique.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        free(self.ptr, self.len, self.locked);
    }
}

/// `N` secret bytes in locked memory, zeroized when dropped.
#[derive(Clone)]
pub struct Secret<const N: usize>(SecretBytes);

impl<const N: usize> Secret<N> {
    /// `N` zero bytes.
    pub fn zeroed() -> Self {
        Self(SecretBytes::zeroed(N))
    }

    /// Move `a` into locked memory (the copy passed in is zeroized).
    pub fn new(mut a: [u8; N]) -> Self {
        let mut s = Self::zeroed();
        s.copy_from_slice(&a);
        a.zeroize();
        s
    }

    /// A copy of `a`.
    pub fn from_ref(a: &[u8; N]) -> Self {
        let mut s = Self::zeroed();
        s.copy_from_slice(a);
        s
    }
}

impl<const N: usize> Deref for Secret<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        // SAFETY: the allocation holds exactly `N` initialized bytes, and
        // `[u8; N]` has alignment 1.
        unsafe { &*(self.0.ptr.as_ptr() as *const [u8; N]) }
    }
}

impl<const N: usize> DerefMut for Secret<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as for `deref`, and `&mut self` makes the access unique.
        unsafe { &mut *(self.0.ptr.as_ptr() as *mut [u8; N]) }
    }
}

/// A value kept in locked memory, like a `Box` (for key types from other
/// crates that hold their key material inline). When dropped, the value's
/// own `Drop` runs and then its bytes are zeroized.
pub struct Locked<T> {
    mem: SecretBytes,
    _owns: std::marker::PhantomData<T>,
}

// SAFETY: `Locked<T>` owns its `T` exclusively, like a `Box<T>`.
unsafe impl<T: Send> Send for Locked<T> {}
// SAFETY: shared access gives `&T` only.
unsafe impl<T: Sync> Sync for Locked<T> {}

impl<T> Locked<T> {
    /// Move `value` into locked memory.
    pub fn new(value: T) -> Self {
        // Slots are power-of-two sized at multiples of their size from a
        // page boundary (pages of their own are page-aligned), so a slot
        // of at least `align_of::<T>()` bytes is aligned for `T`.
        let len = std::mem::size_of::<T>().max(std::mem::align_of::<T>());
        let mem = SecretBytes::zeroed(len);
        debug_assert_eq!(mem.ptr.as_ptr() as usize % std::mem::align_of::<T>(), 0);
        // SAFETY: the slot is at least `size_of::<T>()` bytes, aligned for
        // `T` (above), and owned by `mem`; nothing is there to drop.
        unsafe { std::ptr::write(mem.ptr.as_ptr().cast::<T>(), value) };
        Self {
            mem,
            _owns: std::marker::PhantomData,
        }
    }
}

impl<T> Deref for Locked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `new` wrote a valid `T` there, owned by `self`.
        unsafe { &*self.mem.ptr.as_ptr().cast::<T>() }
    }
}

impl<T> DerefMut for Locked<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`, and `&mut self` makes the access unique.
        unsafe { &mut *self.mem.ptr.as_ptr().cast::<T>() }
    }
}

impl<T> Drop for Locked<T> {
    fn drop(&mut self) {
        // SAFETY: the `T` written by `new` is dropped exactly once, here;
        // `mem` then zeroizes and frees the bytes.
        unsafe { std::ptr::drop_in_place(self.mem.ptr.as_ptr().cast::<T>()) }
    }
}

#[cfg(unix)]
mod os {
    pub fn page_size() -> Option<usize> {
        // SAFETY: sysconf has no preconditions.
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(p).ok()
    }

    pub fn lock(ptr: *mut u8, len: usize) -> bool {
        #[cfg(target_os = "linux")]
        // SAFETY: the range is a whole-page allocation we own; MADV_DONTDUMP
        // only changes how a core dump treats it.
        unsafe {
            libc::madvise(ptr.cast(), len, libc::MADV_DONTDUMP);
        }
        // SAFETY: as above; mlock only pins the pages.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }

    pub fn unlock(ptr: *mut u8, len: usize) {
        // SAFETY: the range is a whole-page allocation we own.
        unsafe {
            libc::munlock(ptr.cast(), len);
        }
    }
}

#[cfg(windows)]
mod os {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    pub fn page_size() -> Option<usize> {
        // SAFETY: GetSystemInfo fills the struct it is given.
        let info = unsafe {
            let mut info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut info);
            info
        };
        usize::try_from(info.dwPageSize).ok()
    }

    pub fn lock(ptr: *mut u8, len: usize) -> bool {
        // SAFETY: the range is a whole-page allocation we own.
        unsafe { VirtualLock(ptr.cast(), len) != 0 }
    }

    pub fn unlock(ptr: *mut u8, len: usize) {
        // SAFETY: the range is a whole-page allocation we own.
        unsafe {
            VirtualUnlock(ptr.cast(), len);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod os {
    pub fn page_size() -> Option<usize> {
        None
    }
    pub fn lock(_ptr: *mut u8, _len: usize) -> bool {
        false
    }
    pub fn unlock(_ptr: *mut u8, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_share_locked_pages_and_are_zeroized() {
        let a = Secret::<32>::new([7; 32]);
        let mut b = SecretBytes::from_slice(&[1, 2, 3]);
        assert_eq!(*a, [7; 32]);
        assert_eq!(&*b, &[1, 2, 3]);
        b[0] = 9;
        assert_eq!(b.clone()[0], 9);
        let big = SecretBytes::from_slice(&vec![5u8; 3 * page_size() + 1]);
        assert!(big.iter().all(|&x| x == 5));
        let s = stats();
        assert!(s.locked_bytes > 0 || s.lock_failures > 0);
        // Many small secrets: one locked page per slot size, not one each.
        let many: Vec<Secret<32>> = (0..64u8).map(|i| Secret::new([i; 32])).collect();
        for (i, m) in many.iter().enumerate() {
            assert_eq!(m[0], i as u8);
        }
        let pages_for_32 = arena().iter().filter(|p| p.slot == 32).count();
        assert!(
            pages_for_32 <= 1 + 64 * 32 / page_size() + 1,
            "{pages_for_32}"
        );
        // A freed slot comes back zeroized.
        let addr = a.as_ptr() as usize;
        drop(a);
        let c = Secret::<32>::zeroed();
        if c.as_ptr() as usize == addr {
            assert_eq!(*c, [0; 32]);
        }
        drop(many);
        drop(big);
        drop(b);
    }

    #[test]
    fn locked_values_drop_once() {
        use std::sync::Arc;
        let rc = Arc::new(5u64);
        {
            let l = Locked::new((Arc::clone(&rc), [3u64; 40]));
            assert_eq!(Arc::strong_count(&rc), 2);
            assert_eq!(l.1[39], 3);
            assert_eq!(l.0.as_ref(), &5);
        }
        assert_eq!(Arc::strong_count(&rc), 1, "dropped once");
        #[repr(align(64))]
        struct Aligned([u8; 8]);
        let a = Locked::new(Aligned([1; 8]));
        assert_eq!(&*a as *const Aligned as usize % 64, 0);
        assert_eq!(a.0, [1; 8]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pages_are_locked() {
        let s = Secret::<64>::new([1; 64]);
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let locked_kb: u64 = status
            .lines()
            .find(|l| l.starts_with("VmLck:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        assert!(
            locked_kb > 0 || stats().lock_failures > 0,
            "VmLck {locked_kb} kB"
        );
        drop(s);
    }
}
