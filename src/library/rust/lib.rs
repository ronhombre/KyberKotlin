#![no_std]
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::slice;
use kyberrust::{KyberError, ffi};

use kyberrust::constants::*;

#[cfg(test)]
mod tests;

const SUCCESS: i32 = 0;
const INVALID_KEY: i32 = 1;
const RANDOM_FAILURE: i32 = 2;
const UNSUPPORTED_VARIANT: i32 = 3;
const BUFFER_TOO_SMALL: i32 = 4;
const MISMATCHING_VARIANT: i32 = 5;
const INVALID_BUFFER: i32 = 6;

fn status(result: Result<(), KyberError>) -> i32 {
    match result {
        Ok(()) => SUCCESS,
        Err(KyberError::InvalidKyberKey) => INVALID_KEY,
        Err(KyberError::RandomBitGeneration) => RANDOM_FAILURE,
        Err(KyberError::UnsupportedKyberVariant) => UNSUPPORTED_VARIANT,
        Err(KyberError::BufferTooSmall) => BUFFER_TOO_SMALL,
        Err(KyberError::MismatchingKyberVariant) => MISMATCHING_VARIANT,
    }
}

macro_rules! dispatch {
    ($variant:expr, $operation:ident, $($argument:expr),+ $(,)?) => {
        match $variant {
            2 => status(ffi::$operation(kyberrust::ML_KEM_512, $($argument),+)),
            3 => status(ffi::$operation(kyberrust::ML_KEM_768, $($argument),+)),
            4 => status(ffi::$operation(kyberrust::ML_KEM_1024, $($argument),+)),
            _ => UNSUPPORTED_VARIANT,
        }
    };
}

// Check ranges and mutable aliasing BEFORE constructing Rust references. The
// caller still owns pointer validity and must keep every array alive until return.
fn valid_buffers(buffers: &[(*const u8, usize, bool)]) -> bool {
    for (i, &(pointer, length, writable)) in buffers.iter().enumerate() {
        let start = pointer as usize;
        let Some(end) = start.checked_add(length) else {
            return false;
        };
        if pointer.is_null() || length > isize::MAX as usize {
            return false;
        }
        for &(other, other_length, other_writable) in &buffers[..i] {
            if (writable || other_writable)
                && start < other as usize + other_length
                && (other as usize) < end
            {
                return false;
            }
        }
    }
    true
}

/// Write dkPKE || ek || H(ek) || z. The encapsulation key is a view into this output.
///
/// # Safety
/// All buffers must be live allocations of the supplied sizes, and writable
/// buffers must be exclusive for this call. No pointer is retained after return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_generate(
    variant: u32,
    seeds: *mut u8,
    seeds_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if seeds_len != N_BYTES * 2
        || !valid_buffers(&[(seeds, seeds_len, true), (output, output_len, true)])
    {
        return INVALID_BUFFER;
    }

    unsafe {
        let seeds_slice = slice::from_raw_parts_mut(seeds, seeds_len);
        let (random_seed, pke_seed) = seeds_slice.split_at_mut(N_BYTES);

        let random_seed: &[u8; 32] = (&*random_seed).try_into().unwrap_unchecked();
        let pke_seed: &mut [u8; 32] = pke_seed.try_into().unwrap_unchecked();
        let out_slice = slice::from_raw_parts_mut(output, output_len);

        dispatch!(variant, generate, random_seed, pke_seed, out_slice)
    }
}

/// Write dkPKE || ekPKE. Safety requirements are the same as `kyberrust_generate`.
///
/// # Safety
/// Each buffer must be valid for its size; writable buffers must be exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_generate_pke(
    variant: u32,
    pke_seed: *mut u8,
    pke_seed_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if pke_seed_len != 32
        || !valid_buffers(&[(pke_seed, pke_seed_len, true), (output, output_len, true)])
    {
        return INVALID_BUFFER;
    }
    unsafe {
        let pke_seed_slice = slice::from_raw_parts_mut(pke_seed, pke_seed_len);
        let out_slice = slice::from_raw_parts_mut(output, output_len);

        let pke_seed: &mut [u8; 32] = pke_seed_slice.try_into().unwrap_unchecked();

        dispatch!(variant, generate_pke, pke_seed, out_slice)
    }
}

/// Borrow an encapsulation key and write sharedSecret || ciphertext.
///
/// # Safety
/// Each buffer must be valid for its size; writable buffers must be exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_encapsulate(
    variant: u32,
    key: *const u8,
    key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if !valid_buffers(&[
            (key, key_len, false),
            (output, output_len, true),
        ])
    {
        return INVALID_BUFFER;
    }
    unsafe {
        let key_slice = slice::from_raw_parts(key, key_len);
        let plaintext_slice = slice::from_raw_parts_mut(output, N_BYTES);
        let out_slice = slice::from_raw_parts_mut(output, output_len);

        let plaintext: &mut [u8; 32] = plaintext_slice.try_into().unwrap_unchecked();

        dispatch!(variant, encapsulate, key_slice, plaintext, out_slice)
    }
}

/// Borrow a decapsulation key and ciphertext and write the 32-byte shared secret.
///
/// # Safety
/// Each buffer must be valid for its size; writable buffers must be exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_decapsulate(
    variant: u32,
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if !valid_buffers(&[
        (key, key_len, false),
        (ciphertext, ciphertext_len, false),
        (output, output_len, true),
    ]) {
        return INVALID_BUFFER;
    }
    unsafe {
        let key_slice = slice::from_raw_parts(key, key_len);
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
        let out_slice = slice::from_raw_parts_mut(output, output_len);

        dispatch!(variant, decapsulate, key_slice, ciphertext_slice, out_slice)
    }
}

/// K-PKE encryption; plaintext and randomness are consumed and zeroed.
///
/// # Safety
/// Each buffer must be valid for its size; writable buffers must be exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_encrypt(
    variant: u32,
    key: *const u8,
    key_len: usize,
    buffer: *mut u8,
    buffer_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if buffer_len != N_BYTES * 2
        || !valid_buffers(&[
            (key, key_len, false),
            (buffer, buffer_len, true),
            (output, output_len, true),
        ])
    {
        return INVALID_BUFFER;
    }
    unsafe {
        let key_slice = slice::from_raw_parts(key, key_len);

        let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        let (plaintext, randomness) = buffer_slice.split_at_mut(N_BYTES);

        let plaintext: &mut [u8; 32] = plaintext.try_into().unwrap_unchecked();
        let randomness: &mut [u8; 32] = randomness.try_into().unwrap_unchecked();

        let out_slice = slice::from_raw_parts_mut(output, output_len);

        dispatch!(variant, encrypt, key_slice, plaintext, randomness, out_slice)
    }
}

/// K-PKE decryption; the key and ciphertext are borrowed unchanged.
///
/// # Safety
/// Each buffer must be valid for its size; writable buffers must be exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kyberrust_decrypt(
    variant: u32,
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if !valid_buffers(&[
        (key, key_len, false),
        (ciphertext, ciphertext_len, false),
        (output, output_len, true),
    ]) {
        return INVALID_BUFFER;
    }
    unsafe {
        let key_slice = slice::from_raw_parts(key, key_len);
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
        let out_slice = slice::from_raw_parts_mut(output, output_len);

        dispatch!(variant, decrypt, key_slice, ciphertext_slice, out_slice)
    }
}

#[cfg(not(test))]
unsafe extern "C" {
    fn abort() -> !;
}

// Precompiled compiler_builtins can retain an unwind-personality reference even
// when this crate uses panic=abort. Provide it for the no_std static archive;
// any attempted unwinding terminates rather than crossing into Kotlin.
// Before C interop embeds the archive, Gradle weakens this fallback on ELF/Mach-O
// or renames it and its references to kyberrust_eh_personality on Windows COFF.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() -> ! {
    unsafe { abort() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { abort() }
}
