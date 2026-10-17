//! The sandbox's WASI, with small hand-written programs; and mediad's own
//! WebAssembly build when `ENCLAVE_MEDIAD_WASM` names it (CI).

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Copies standard input to standard output, 64 bytes at a time, then
/// tries to open a file and exits with what that returned.
const ECHO: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $more
      ;; iovec at 0: buffer 100, length 64; count at 8
      (i32.store (i32.const 0) (i32.const 100))
      (i32.store (i32.const 4) (i32.const 64))
      (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
      (if (i32.gt_u (i32.load (i32.const 8)) (i32.const 0))
        (then
          (i32.store (i32.const 4) (i32.load (i32.const 8)))
          (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 12)))
          (br $more))))
    (call $exit (call $open (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 0)
      (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 16)))))
"#;

#[test]
fn standard_input_to_output_and_no_files() {
    let module = wat::parse_str(ECHO).unwrap();
    let text: Vec<u8> = (0..200u8).collect();
    let out = Sink::default();
    let code = enclave_wasmbox::run(&module, Cursor::new(text.clone()), out.clone()).unwrap();
    assert_eq!(*out.0.lock().unwrap(), text);
    assert_eq!(code, 76, "path_open is refused (ENOTCAPABLE)");
}

#[test]
fn memory_is_capped() {
    // Asks for 2 GiB at the start: refused, so the module can't start.
    let module =
        wat::parse_str(r#"(module (memory (export "memory") 32768) (func (export "_start")))"#)
            .unwrap();
    assert!(enclave_wasmbox::run(&module, Cursor::new(Vec::new()), Sink::default()).is_err());
}

#[test]
fn a_trap_is_an_error_not_a_crash() {
    let module = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "_start") unreachable))"#,
    )
    .unwrap();
    assert!(enclave_wasmbox::run(&module, Cursor::new(Vec::new()), Sink::default()).is_err());
}

fn frames(reqs: &[enclave_ipc::media::MediaRequest]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in reqs {
        let body = r.encode();
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

fn replies(mut b: &[u8]) -> Vec<enclave_ipc::media::MediaReply> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        out.push(enclave_ipc::media::MediaReply::decode(&b[4..4 + n]).unwrap());
        b = &b[4 + n..];
    }
    out
}

fn picture() -> Vec<u8> {
    let (w, h) = (64u32, 48u32);
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(png::ColorType::Rgba);
    let mut px = Vec::new();
    for y in 0..h {
        for x in 0..w {
            px.extend_from_slice(&[(x * 4) as u8, (y * 5) as u8, 128, 255]);
        }
    }
    e.write_header().unwrap().write_image_data(&px).unwrap();
    out
}

fn animation() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = gif::Encoder::new(&mut out, 32, 32, &[]).unwrap();
        for i in 0..4u8 {
            let mut px = vec![0u8; 32 * 32 * 4];
            for (k, p) in px.chunks_mut(4).enumerate() {
                p.copy_from_slice(&[i * 60, (k % 32) as u8 * 8, 90, 255]);
            }
            let mut f = gif::Frame::from_rgba(32, 32, &mut px);
            f.delay = 10;
            e.write_frame(&f).unwrap();
        }
    }
    out
}

/// mediad as WebAssembly gives what the same code gives natively: a
/// thumbnail, a clip made from a GIF, and that clip's frames decoded (AV1).
#[test]
fn mediad_in_the_sandbox_matches_native() {
    use enclave_ipc::media::{MediaOp, MediaOut, MediaRequest};
    let Ok(path) = std::env::var("ENCLAVE_MEDIAD_WASM") else {
        eprintln!("ENCLAVE_MEDIAD_WASM not set: mediad's WebAssembly build not checked");
        return;
    };
    let module = std::fs::read(path).unwrap();
    let pic = picture();
    let gif = animation();
    let out = Sink::default();
    let input = frames(&[
        MediaRequest {
            id: 1,
            op: MediaOp::Thumbnail(32),
            bytes: pic.clone(),
        },
        MediaRequest {
            id: 2,
            op: MediaOp::Clip,
            bytes: gif.clone(),
        },
        MediaRequest {
            id: 3,
            op: MediaOp::Thumbnail(32),
            bytes: b"not a picture".to_vec(),
        },
    ]);
    assert_eq!(
        enclave_wasmbox::run(&module, Cursor::new(input), out.clone()).unwrap(),
        0
    );
    let got = replies(&out.0.lock().unwrap());
    assert_eq!(got.len(), 3);
    let native = enclave_media::thumbnail(&pic, 32).unwrap();
    match &got[0].result {
        Ok(MediaOut::Rgba {
            width,
            height,
            pixels,
        }) => {
            assert_eq!((*width, *height), (native.width, native.height));
            assert_eq!(*pixels, native.pixels);
        }
        other => panic!("thumbnail: {other:?}"),
    }
    let clip = match &got[1].result {
        Ok(MediaOut::Clip { bytes, .. }) => bytes.clone(),
        other => panic!("clip: {other:?}"),
    };
    assert!(
        got[2].result.is_err(),
        "a bad picture is an error, not a crash"
    );
    let out = Sink::default();
    let input = frames(&[MediaRequest {
        id: 4,
        op: MediaOp::ClipFrames(32),
        bytes: clip.clone(),
    }]);
    let t = std::time::Instant::now();
    assert_eq!(
        enclave_wasmbox::run(&module, Cursor::new(input), out.clone()).unwrap(),
        0
    );
    eprintln!("clip frames in the sandbox: {:?}", t.elapsed());
    let got = replies(&out.0.lock().unwrap());
    let native =
        enclave_media::video::clip_frames(&clip, 32, enclave_ipc::media::MAX_CLIP_FRAMES).unwrap();
    match &got[0].result {
        Ok(MediaOut::Clip { frames, .. }) => {
            assert_eq!(frames.len(), native.len());
            for (a, b) in frames.iter().zip(&native) {
                assert_eq!(*a, b.pixels);
            }
        }
        other => panic!("clip frames: {other:?}"),
    }
}

/// `random_get` fills the buffer it is given (std seeds its hash maps with
/// it), and refuses one outside memory.
#[test]
fn random_bytes() {
    let module = wat::parse_str(
        r#"(module
          (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (if (call $random (i32.const 70000) (i32.const 8)) (then) (else (call $exit (i32.const 2))))
            (drop (call $random (i32.const 0) (i32.const 37)))
            ;; 37 bytes, not all zero: exit 0; else 1.
            (if (i64.ne (i64.or (i64.load (i32.const 0)) (i64.load (i32.const 29))) (i64.const 0))
              (then (call $exit (i32.const 0)))
              (else (call $exit (i32.const 1))))))"#,
    )
    .unwrap();
    assert_eq!(
        enclave_wasmbox::run(&module, Cursor::new(Vec::new()), Sink::default()).unwrap(),
        0
    );
}
