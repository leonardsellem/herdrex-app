//! Rex starts each terminal stream with a Ghostty snapshot. The app's
//! terminals read VT bytes, so the bridge restores the snapshot here and
//! paints it again as escape sequences: the "first paint" herdr-core sends.

use ghostty_sys::*;
use std::ffi::c_void;

/// The snapshot as VT bytes: modes, colors, the screen, at most `history`
/// rows of scrollback above it, then any half-written escape sequence the
/// program was in the middle of. None if the snapshot can't be read.
pub fn to_vt(snapshot: &[u8], history: usize) -> Option<Vec<u8>> {
    unsafe {
        let mut decoder = std::ptr::null_mut();
        if ghostty_snapshot_decoder_new_buf(std::ptr::null(), &mut decoder, snapshot.as_ptr(), snapshot.len()) != GHOSTTY_SUCCESS {
            return None;
        }
        let retain = true;
        ghostty_snapshot_decoder_set(decoder, GHOSTTY_SNAPSHOT_DECODER_OPT_RETAIN_CONTINUATION, &retain as *const bool as *const c_void);
        let mut term = std::ptr::null_mut();
        if ghostty_snapshot_decoder_ready(decoder, &mut term) != GHOSTTY_SUCCESS || term.is_null() {
            ghostty_snapshot_decoder_free(decoder);
            return None;
        }
        // History pages come newest first: stop once there are enough rows.
        let mut restored = 0usize;
        while restored < history && ghostty_snapshot_decoder_next(decoder) == GHOSTTY_SUCCESS {
            let mut rows = 0usize;
            ghostty_snapshot_decoder_get(decoder, GHOSTTY_SNAPSHOT_DECODER_DATA_PROGRESS_ROWS, &mut rows as *mut usize as *mut c_void);
            restored += rows;
        }
        ghostty_snapshot_decoder_free(decoder);
        let out = format_vt(term);
        let tail = continuation(term);
        ghostty_terminal_free(term);
        out.map(|mut vt| {
            vt.extend(tail);
            vt
        })
    }
}

unsafe fn format_vt(term: GhosttyTerminal) -> Option<Vec<u8>> {
    let screen = GhosttyFormatterScreenExtra {
        size: std::mem::size_of::<GhosttyFormatterScreenExtra>(),
        cursor: true,
        style: true,
        hyperlink: true,
        protection: true,
        kitty_keyboard: true,
        charsets: true,
    };
    let extra = GhosttyFormatterTerminalExtra {
        size: std::mem::size_of::<GhosttyFormatterTerminalExtra>(),
        palette: true,
        modes: true,
        scrolling_region: true,
        tabstops: true,
        pwd: true,
        keyboard: true,
        screen,
    };
    let options = GhosttyFormatterTerminalOptions {
        size: std::mem::size_of::<GhosttyFormatterTerminalOptions>(),
        emit: GHOSTTY_FORMATTER_FORMAT_VT,
        unwrap: false,
        trim: false,
        extra,
        selection: std::ptr::null(),
    };
    unsafe {
        let mut formatter = std::ptr::null_mut();
        if ghostty_formatter_terminal_new(std::ptr::null(), &mut formatter, term, options) != GHOSTTY_SUCCESS {
            return None;
        }
        let (mut ptr, mut len) = (std::ptr::null_mut(), 0usize);
        let result = ghostty_formatter_format_alloc(formatter, std::ptr::null(), &mut ptr, &mut len);
        ghostty_formatter_free(formatter);
        if result != GHOSTTY_SUCCESS {
            return None;
        }
        Some(take(ptr, len))
    }
}

/// The unfinished escape sequence the snapshot was cut in, so the bytes after it parse.
unsafe fn continuation(term: GhosttyTerminal) -> Vec<u8> {
    unsafe {
        let (mut ptr, mut len) = (std::ptr::null_mut(), 0usize);
        if ghostty_terminal_continuation_alloc(term, std::ptr::null(), &mut ptr, &mut len) != GHOSTTY_SUCCESS {
            return Vec::new();
        }
        take(ptr, len)
    }
}

unsafe fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    unsafe {
        let bytes = std::slice::from_raw_parts(ptr, len).to_vec();
        ghostty_free(std::ptr::null(), ptr, len);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot made by this Ghostty paints back the same screen.
    #[test]
    fn a_snapshot_paints_back_as_vt() {
        unsafe {
            let mut term = std::ptr::null_mut();
            assert_eq!(ghostty_terminal_new(std::ptr::null(), &mut term, 20, 4), GHOSTTY_SUCCESS);
            let text = b"\x1b[1mbold\x1b[0m line\r\nsecond";
            ghostty_terminal_vt_write(term, text.as_ptr(), text.len());
            let (mut ptr, mut len) = (std::ptr::null_mut(), 0usize);
            assert_eq!(ghostty_snapshot_encode_alloc(term, std::ptr::null(), &mut ptr, &mut len), GHOSTTY_SUCCESS);
            let snapshot = take(ptr, len);
            ghostty_terminal_free(term);
            let vt = to_vt(&snapshot, 100).expect("decodes");
            let shown = String::from_utf8_lossy(&vt);
            assert!(shown.contains("bold"), "{shown:?}");
            assert!(shown.contains("second"), "{shown:?}");
            assert!(to_vt(b"not a snapshot", 0).is_none());
        }
    }
}
