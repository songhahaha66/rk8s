//! File handle and descriptor management

use crate::meta::store::FileAttr;
use std::time::Instant;

#[allow(dead_code)]
pub struct FileHandle {
    pub fh: u64,
    pub ino: i64,
    pub attr: FileAttr,
    pub opened_at: Instant,
    pub last_offset: u64,
    pub flags: HandleFlags,
}

impl FileHandle {
    pub fn new(fh: u64, ino: i64, attr: FileAttr, flags: HandleFlags) -> Self {
        Self {
            fh,
            ino,
            attr,
            opened_at: Instant::now(),
            last_offset: 0,
            flags,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct HandleFlags {
    read: bool,
    write: bool,
}

impl HandleFlags {
    pub const fn new(read: bool, write: bool) -> Self {
        Self { read, write }
    }
}
