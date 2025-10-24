// Copyright (C) 2023 Ant Group. All rights reserved.
//  2024 From [fuse_backend_rs](https://github.com/cloud-hypervisor/fuse-backend-rs)
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
mod async_io;
pub mod config;
mod inode_store;
mod layer;
mod utils;

//mod tempfile;
use core::panic;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io::{Error, Result};
use std::path::Path;

use config::Config;
use futures::StreamExt as _;
use rfuse3::raw::reply::{
    DirectoryEntry, DirectoryEntryPlus, ReplyAttr, ReplyEntry, ReplyOpen, ReplyStatFs,
};
use rfuse3::raw::{Request, Session};
use std::sync::{Arc, Weak};
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;

use rfuse3::{Errno, FileType, MountOptions, mode_from_kind_and_perm};
const SLASH_ASCII: char = '/';
use futures::future::join_all;
use futures::stream::iter;

use crate::passthrough::newlogfs::LoggingFileSystem;
use crate::passthrough::{PassthroughArgs, new_passthroughfs_layer};
use crate::util::convert_stat64_to_file_attr;
use inode_store::InodeStore;
use layer::Layer;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{Mutex, RwLock};

pub type Inode = u64;
pub type Handle = u64;




// RealInode represents one inode object in specific layer.
// Also, each RealInode maps to one Entry, which should be 'forgotten' after drop.
// Important note: do not impl Clone trait for it or refcount will be messed up.
pub(crate) struct RealInode<L: Layer + Send + Sync + 'static> {
    pub layer: Arc<L>,
    pub in_upper_layer: bool,
    pub inode: u64,
    // File is whiteouted, we need to hide it.
    pub whiteout: bool,
    // Directory is opaque, we need to hide all entries inside it.
    pub opaque: bool,
    pub stat: Option<ReplyAttr>,
}

const INODE_ALLOC_BATCH: u64 = 0x1_0000_0000;

// OverlayInode must be protected by lock, it can be operated by multiple threads.
// #[derive(Default)]
pub(crate) struct OverlayInode<L: Layer + Send + Sync + 'static> {
    // Inode hash table, map from 'name' to 'OverlayInode'.
    pub childrens: Mutex<HashMap<String, Arc<OverlayInode<L>>>>,
    pub parent: Mutex<Weak<OverlayInode<L>>>,
    // Backend inodes from all layers.
    pub real_inodes: Mutex<Vec<Arc<RealInode<L>>>>,
    // Inode number.
    pub inode: u64,
    pub path: RwLock<String>,
    pub name: RwLock<String>,
    pub lookups: AtomicU64,
    // Node is whiteout-ed.
    pub whiteout: AtomicBool,
    // Directory is loaded.
    pub loaded: AtomicBool,
}

#[derive(Default)]
pub enum CachePolicy {
    Never,
    #[default]
    Auto,
    Always,
}

/// OverlayFs is a generic filesystem that supports multiple layers.
/// It is parameterized by a type `L` that implements the `Layer` trait.
pub struct OverlayFs<L: Layer + Send + Sync + 'static> {
    config: Config,
    lower_layers: Vec<Arc<L>>,
    upper_layer: Option<Arc<L>>,
    // All inodes in FS.
    inodes: RwLock<InodeStore<L>>,
    // Open file handles.
    handles: Mutex<HashMap<u64, Arc<HandleData<L>>>>,
    next_handle: AtomicU64,
    writeback: AtomicBool,
    no_open: AtomicBool,
    no_opendir: AtomicBool,
    killpriv_v2: AtomicBool,
    perfile_dax: AtomicBool,
    root_inodes: u64,
}

// This is a wrapper of one inode in specific layer, It can't impl Clone trait.
struct RealHandle<L: Layer + Send + Sync + 'static> {
    layer: Arc<L>,
    in_upper_layer: bool,
    inode: u64,
    handle: AtomicU64,
}

struct HandleData<L: Layer + Send + Sync + 'static> {
    node: Arc<OverlayInode<L>>,
    //offset: libc::off_t,
    real_handle: Option<RealHandle<L>>,
}

// RealInode is a wrapper of one inode in specific layer.
// All layer operations returning Entry should be wrapped in RealInode implementation
// so that we can increase the refcount(lookup count) of each inode and decrease it after Drop.
// Important: do not impl 'Copy' trait for it or refcount will be messed up.
impl<L: Layer> RealInode<L> {
    async fn new(
        layer: Arc<L>,
        in_upper_layer: bool,
        inode: u64,
        whiteout: bool,
        opaque: bool,
    ) -> Self {
        let mut ri = RealInode {
            layer,
            in_upper_layer,
            inode,
            whiteout,
            opaque,
            stat: None,
        };
        match ri.stat64_ignore_enoent(&Request::default()).await {
            Ok(v) => {
                ri.stat = v;
            }
            Err(e) => {
                error!("stat64 failed during RealInode creation: {e}");
            }
        }
        ri
    }

    async fn stat64(&self, req: &Request) -> Result<ReplyAttr> {
                if self.inode == 0 {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }
        // trace!("stat64: trying to getattr req: {:?}", req);
        self.layer
            .getattr(*req, self.inode, None, 0)
            .await
            .map_err(|e| e.into())
    }

    async fn stat64_ignore_enoent(&self, req: &Request) -> Result<Option<ReplyAttr>> {
        match self.stat64(req).await {
            Ok(v1) => Ok(Some(v1)),
            Err(e) => match e.raw_os_error() {
                Some(raw_error) => {
                    if raw_error != libc::ENOENT || raw_error != libc::ENAMETOOLONG {
                        return Ok(None);
                    }
                    Err(e)
                }
                None => Err(e),
            },
        }
    }

    // Do real lookup action in specific layer, this call will increase Entry refcount which must be released later.
    async fn lookup_child_ignore_enoent(
        &self,
        ctx: Request,
        name: &str,
    ) -> Result<Option<ReplyEntry>> {
        let cname = OsStr::new(name);
        // Real inode must have a layer.
                match self.layer.lookup(ctx, self.inode, cname).await {
            Ok(v) => {
                // Negative entry also indicates missing entry.
                if v.attr.ino == 0 {
                    return Ok(None);
                }
                Ok(Some(v))
            }
            Err(e) => {
                let ioerror: std::io::Error = e.into();
                if let Some(raw_error) = ioerror.raw_os_error()
                    && (raw_error == libc::ENOENT || raw_error == libc::ENAMETOOLONG)
                {
                    return Ok(None);
                }

                Err(e.into())
            }
        }
    }

    // Find child inode in same layer under this directory(Self).
    // Return None if not found.
    async fn lookup_child(&self, ctx: Request, name: &str) -> Result<Option<RealInode<L>>> {
        if self.whiteout {
            return Ok(None);
        }

        
        // Find child Entry with <name> under directory with inode <self.inode>.
        match self.lookup_child_ignore_enoent(ctx, name).await? {
            Some(v) => {
                // The Entry must be forgotten in each layer, which will be done automatically by Drop operation.
                let (whiteout, opaque) = if v.attr.kind == FileType::Directory {
                    (false, false)
                } else {
                    (false, false)
                };

                Ok(Some(RealInode {
                    layer: self.layer.clone(),
                    in_upper_layer: self.in_upper_layer,
                    inode: v.attr.ino,
                    whiteout,
                    opaque,
                    stat: Some(ReplyAttr {
                        ttl: v.ttl,
                        attr: v.attr,
                    }),
                }))
            }
            None => Ok(None),
        }
    }

    // Read directory entries from specific RealInode, error out if it's not directory.
    async fn readdir(&self, ctx: Request) -> Result<HashMap<String, RealInode<L>>> {
        // Deleted inode should not be read.
        if self.whiteout {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }
        // trace!("readdir: before stat");
        let stat = match self.stat.clone() {
            Some(v) => v,
            None => self.stat64(&ctx).await?,
        };

        // Must be directory.
        if stat.attr.kind != FileType::Directory {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        // Open the directory and load each entry.
        let opendir_res = self
            .layer
            .opendir(ctx, self.inode, libc::O_RDONLY as u32)
            .await;
        // trace!("readdir: after opendir");
        let handle = match opendir_res {
            Ok(handle) => handle,

            // opendir may not be supported if no_opendir is set, so we can ignore this error.
            Err(e) => {
                let ioerror: std::io::Error = e.into();
                match ioerror.raw_os_error() {
                    Some(raw_error) => {
                        if raw_error == libc::ENOSYS {
                            // We can still call readdir with inode if opendir is not supported in this layer.
                            ReplyOpen { fh: 0, flags: 0 }
                        } else {
                            return Err(e.into());
                        }
                    }
                    None => {
                        return Err(e.into());
                    }
                }
            }
        };

        let child_names = self.layer.readdir(ctx, self.inode, handle.fh, 0).await?;
        // Non-zero handle indicates successful 'open', we should 'release' it.
        if handle.fh > 0 {
            self.layer
                .releasedir(ctx, self.inode, handle.fh, handle.flags)
                .await?
            //DIFF
        }

        // Lookup all child and construct "RealInode"s.
        let child_real_inodes = Arc::new(Mutex::new(HashMap::new()));
        // trace!("readdir: before iter childrens");
        let a_map = child_names.entries.map(|entery| async {
            match entery {
                Ok(dire) => {
                    let dname = dire.name.into_string().unwrap();
                    if dname == "." || dname == ".." {
                        // Skip . and .. entries.
                        return Ok(());
                    }
                    // trace!("readdir: before lookup child: dname={}", dname);
                    if let Some(child) = self.lookup_child(ctx, &dname).await? {
                        child_real_inodes.lock().await.insert(dname, child);
                    }
                    Ok(())
                }
                Err(err) => Err(err),
            }
        });
        let k = join_all(a_map.collect::<Vec<_>>().await).await;
        drop(k);
        // Now into_inner func is safety.
        let re = Arc::try_unwrap(child_real_inodes)
            .map_err(|_| Errno::new_not_exist())?
            .into_inner();
        // trace!("readdir: return");
        Ok(re)
    }

    async fn create_whiteout(&self, ctx: Request, name: &str) -> Result<RealInode<L>> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // from &str to &OsStr
        let name_osstr = OsStr::new(name);
        let entry = self
            .layer
            .create_whiteout(ctx, self.inode, name_osstr)
            .await?;

        // Wrap whiteout to RealInode.
        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: true,
            inode: entry.attr.ino,
            whiteout: true,
            opaque: false,
            stat: Some(ReplyAttr {
                ttl: entry.ttl,
                attr: entry.attr,
            }),
        })
    }

    async fn mkdir(&self, ctx: Request, name: &str, mode: u32, umask: u32) -> Result<RealInode<L>> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let name_osstr = OsStr::new(name);
        let entry = self
            .layer
            .mkdir(ctx, self.inode, name_osstr, mode, umask)
            .await?;

        // update node's first_layer
        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: true,
            inode: entry.attr.ino,
            whiteout: false,
            opaque: false,
            stat: Some(ReplyAttr {
                ttl: entry.ttl,
                attr: entry.attr,
            }),
        })
    }

    async fn create(
        &self,
        ctx: Request,
        name: &str,
        mode: u32,
        flags: u32,
    ) -> Result<(RealInode<L>, Option<u64>)> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }
        let name = OsStr::new(name);
        let create_rep = self
            .layer
            .create(ctx, self.inode, name, mode, flags)
            .await?;

        Ok((
            RealInode {
                layer: self.layer.clone(),
                in_upper_layer: true,
                inode: create_rep.attr.ino,
                whiteout: false,
                opaque: false,
                stat: Some(ReplyAttr {
                    ttl: create_rep.ttl,
                    attr: create_rep.attr,
                }),
            },
            Some(create_rep.fh),
        ))
    }

    async fn mknod(
        &self,
        ctx: Request,
        name: &str,
        mode: u32,
        rdev: u32,
        _umask: u32,
    ) -> Result<RealInode<L>> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }
        let name = OsStr::new(name);
        let rep = self.layer.mknod(ctx, self.inode, name, mode, rdev).await?;
        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: true,
            inode: rep.attr.ino,
            whiteout: false,
            opaque: false,
            stat: Some(ReplyAttr {
                ttl: rep.ttl,
                attr: rep.attr,
            }),
        })
    }

    async fn link(&self, ctx: Request, ino: u64, name: &str) -> Result<RealInode<L>> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }
        let name = OsStr::new(name);
        let entry = self.layer.link(ctx, ino, self.inode, name).await?;

        let opaque = if utils::is_dir(&entry.attr.kind) {
            false
        } else {
            false
        };
        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: true,
            inode: entry.attr.ino,
            whiteout: false,
            opaque,
            stat: Some(ReplyAttr {
                ttl: entry.ttl,
                attr: entry.attr,
            }),
        })
    }

    // Create a symlink in self directory.
    async fn symlink(&self, ctx: Request, link_name: &str, filename: &str) -> Result<RealInode<L>> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }
        let link_name = OsStr::new(link_name);
        let filename = OsStr::new(filename);
        let entry = self
            .layer
            .symlink(ctx, self.inode, filename, link_name)
            .await?;

        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: true,
            inode: entry.attr.ino,
            whiteout: false,
            opaque: false,
            stat: Some(ReplyAttr {
                ttl: entry.ttl,
                attr: entry.attr,
            }),
        })
    }
}

impl<L: Layer + Send + Sync + 'static> Drop for RealInode<L> {
    fn drop(&mut self) {
        let layer = Arc::clone(&self.layer);
        let inode = self.inode;
        tokio::spawn(async move {
            let ctx = Request::default();
            layer.forget(ctx, inode, 1).await;
        });
    }
}

impl<L: Layer + Send + Sync + 'static> OverlayInode<L> {
    pub fn new() -> Self {
        Self {
            childrens: Mutex::new(HashMap::new()),
            parent: Mutex::new(Weak::new()),
            real_inodes: Mutex::new(vec![]),
            inode: 0,
            path: RwLock::new(String::new()),
            name: RwLock::new(String::new()),
            lookups: AtomicU64::new(0),
            whiteout: AtomicBool::new(false),
            loaded: AtomicBool::new(false),
        }
    }
    // Allocate new OverlayInode based on one RealInode,
    // inode number is always 0 since only OverlayFs has global unique inode allocator.
    pub async fn new_from_real_inode(
        name: &str,
        ino: u64,
        path: String,
        real_inode: RealInode<L>,
    ) -> Self {
        let mut new = OverlayInode::new();
        new.inode = ino;
        new.path = path.into();
        new.name = name.to_string().into();
        new.whiteout.store(real_inode.whiteout, Ordering::Relaxed);
        new.lookups = AtomicU64::new(1);
        new.real_inodes = Mutex::new(vec![real_inode.into()]);
        new
    }

    pub async fn new_from_real_inodes(
        name: &str,
        ino: u64,
        path: String,
        real_inodes: Vec<RealInode<L>>,
    ) -> Result<Self> {
        if real_inodes.is_empty() {
            error!("BUG: new_from_real_inodes() called with empty real_inodes");
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        let mut first = true;
        let mut new = Self::new();
        for ri in real_inodes {
            let whiteout = ri.whiteout;
            let opaque = ri.opaque;
            let stat = match &ri.stat {
                Some(v) => v.clone(),
                None => ri.stat64(&Request::default()).await?,
            };

            if first {
                first = false;
                new = Self::new_from_real_inode(name, ino, path.clone(), ri).await;

                // This is whiteout, no need to check lower layers.
                if whiteout {
                    break;
                }

                // A non-directory file shadows all lower layers as default.
                if !utils::is_dir(&stat.attr.kind) {
                    break;
                }

                // Opaque directory shadows all lower layers.
                if opaque {
                    break;
                }
            } else {
                // This is whiteout, no need to record this, break directly.
                if ri.whiteout {
                    break;
                }

                // Only directory have multiple real inodes, so if this is non-first real-inode
                // and it's not directory, it should indicates some invalid layout. @weizhang555
                if !utils::is_dir(&stat.attr.kind) {
                    error!("invalid layout: non-directory has multiple real inodes");
                    break;
                }

                // Valid directory.
                new.real_inodes.lock().await.push(ri.into());
                // Opaque directory shadows all lower layers.
                if opaque {
                    break;
                }
            }
        }
        Ok(new)
    }

    pub async fn stat64(&self, ctx: Request) -> Result<ReplyAttr> {
        // try layers in order or just take stat from first layer?
        for l in self.real_inodes.lock().await.iter() {
            if let Some(v) = l.stat64_ignore_enoent(&ctx).await? {
                return Ok(v);
            }
        }

        // not in any layer
        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    pub async fn is_dir(&self, ctx: Request) -> Result<bool> {
        let st = self.stat64(ctx).await?;
        Ok(utils::is_dir(&st.attr.kind))
    }

    pub async fn count_entries_and_whiteout(&self, ctx: Request) -> Result<(u64, u64)> {
        let mut count = 0;
        let mut whiteouts = 0;

        let st = self.stat64(ctx).await?;

        // must be directory
        if !utils::is_dir(&st.attr.kind) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        for (_, child) in self.childrens.lock().await.iter() {
            if child.whiteout.load(Ordering::Relaxed) {
                whiteouts += 1;
            } else {
                count += 1;
            }
        }
        Ok((count, whiteouts))
    }

    pub async fn open(
        &self,
        ctx: Request,
        flags: u32,
        _fuse_flags: u32,
    ) -> Result<(Arc<L>, ReplyOpen)> {
        let (layer, _, inode) = self.first_layer_inode().await;
        let ro = layer.as_ref().open(ctx, inode, flags).await?;
        Ok((layer, ro))
    }

    // Self is directory, fill all childrens.
    pub async fn scan_childrens(self: &Arc<Self>, ctx: Request) -> Result<Vec<OverlayInode<L>>> {
        let st = self.stat64(ctx).await?;
        if !utils::is_dir(&st.attr.kind) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        let mut all_layer_inodes: HashMap<String, Vec<RealInode<L>>> = HashMap::new();
        // read out directories from each layer
        // Scan from upper layer to lower layer.
        for ri in self.real_inodes.lock().await.iter() {
            if ri.whiteout {
                // Node is deleted from some upper layer, skip it.
                debug!("directory is whiteout");
                break;
            }

            let stat = match &ri.stat {
                Some(v) => v.clone(),
                None => ri.stat64(&ctx).await?,
            };

            if !utils::is_dir(&stat.attr.kind) {
                debug!("{} is not a directory", self.path.read().await);
                // not directory
                break;
            }

            // Read all entries from one layer.
            let entries: HashMap<String, RealInode<L>> = ri.readdir(ctx).await?;

            // Merge entries from one layer to all_layer_inodes.
            for (name, inode) in entries {
                match all_layer_inodes.get_mut(&name) {
                    Some(v) => {
                        // Append additional RealInode to the end of vector.
                        v.push(inode)
                    }
                    None => {
                        all_layer_inodes.insert(name, vec![inode]);
                    }
                }
            }

            // if opaque, stop here
            if ri.opaque {
                debug!("directory {} is opaque", self.path.read().await);
                break;
            }
        }

        // Construct OverlayInode for each entry.
        let mut childrens = vec![];
        for (name, real_inodes) in all_layer_inodes {
            // Inode numbers are not allocated yet.
            let path = format!("{}/{}", self.path.read().await, name);
            let new = Self::new_from_real_inodes(name.as_str(), 0, path, real_inodes).await?;
            childrens.push(new);
        }

        Ok(childrens)
    }

    /// Create a new directory in upper layer for node, node must be directory.
    ///
    /// Recursively ensures a directory path exists in the upper layer.
    ///
    /// This function is a critical part of the copy-up process. When a file or directory
    /// needs to be copied up, this function is called on its parent to ensure the entire
    /// directory hierarchy exists in the upper layer first. It works recursively:
    /// 1. If the current directory is already in the upper layer, it does nothing.
    /// 2. If not, it first calls itself on its own parent directory.
    /// 3. Once the parent is guaranteed to be in the upper layer, it creates the current
    ///    directory within the parent's upper-layer representation.
    ///
    /// Crucially, it preserves the original directory's ownership (UID/GID) and permissions
    /// by using the [`getattr_helper`][crate::overlayfs::layer::Layer::getattr_helper] and
    /// [`mkdir_helper`][crate::overlayfs::layer::Layer::mkdir_helper] methods.
    pub async fn create_upper_dir(
        self: Arc<Self>,
        ctx: Request,
        mode_umask: Option<(u32, u32)>,
    ) -> Result<()> {
        // To preserve original ownership, we must get the raw, unmapped host attributes.
        // We achieve this by calling `getattr_helper`, which is specifically designed
        // to bypass the ID mapping logic. This is safe and does not affect other
        // functionalities because `getattr_helper` and the standard `stat64()` call
        // both rely on the same underlying `stat` system call; they only differ in
        // whether the resulting `uid` and `gid` are mapped.
        let (self_layer, _, self_inode) = self.first_layer_inode().await;
        let re = self_layer.getattr_helper(self_inode, None).await?;
        let st = ReplyAttr {
            ttl: re.1,
            attr: convert_stat64_to_file_attr(re.0),
        };
        if !utils::is_dir(&st.attr.kind) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        // If node already has upper layer, we can just return here.
        if self.in_upper_layer().await {
            return Ok(());
        }

        // not in upper layer, check parent.
        let pnode = if let Some(n) = self.parent.lock().await.upgrade() {
            Arc::clone(&n)
        } else {
            return Err(Error::other("no parent?"));
        };

        if !pnode.in_upper_layer().await {
            Box::pin(pnode.clone().create_upper_dir(ctx, None)).await?; // recursive call
        }
        let child: Arc<Mutex<Option<RealInode<L>>>> = Arc::new(Mutex::new(None));
        let c_name = self.name.read().await.clone();
        let _ = pnode
            .handle_upper_inode_locked(&mut |parent_upper_inode: Option<Arc<RealInode<L>>>| async {
                match parent_upper_inode {
                    Some(parent_ri) => {
                        let ri = match mode_umask {
                            // We manually unfold the `mkdir` logic here instead of calling the `mkdir` method directly.
                            // This is necessary to preserve the original directory's UID and GID during the copy-up process.
                            Some((mode, umask)) => {
                                if !parent_ri.in_upper_layer {
                                    return Err(Error::from_raw_os_error(libc::EROFS));
                                }
                                let name_osstr = OsStr::new(&c_name);
                                let entry = parent_ri
                                    .layer
                                    .mkdir_helper(
                                        ctx,
                                        parent_ri.inode,
                                        name_osstr,
                                        mode,
                                        umask,
                                        st.attr.uid,
                                        st.attr.gid,
                                    )
                                    .await?;
                                RealInode {
                                    layer: parent_ri.layer.clone(),
                                    in_upper_layer: true,
                                    inode: entry.attr.ino,
                                    whiteout: false,
                                    opaque: false,
                                    stat: Some(ReplyAttr {
                                        ttl: entry.ttl,
                                        attr: entry.attr,
                                    }),
                                }
                            }
                            None => {
                                if !parent_ri.in_upper_layer {
                                    return Err(Error::from_raw_os_error(libc::EROFS));
                                }
                                let name_osstr = OsStr::new(&c_name);
                                let entry = parent_ri
                                    .layer
                                    .mkdir_helper(
                                        ctx,
                                        parent_ri.inode,
                                        name_osstr,
                                        mode_from_kind_and_perm(st.attr.kind, st.attr.perm),
                                        0,
                                        st.attr.uid,
                                        st.attr.gid,
                                    )
                                    .await?;
                                RealInode {
                                    layer: parent_ri.layer.clone(),
                                    in_upper_layer: true,
                                    inode: entry.attr.ino,
                                    whiteout: false,
                                    opaque: false,
                                    stat: Some(ReplyAttr {
                                        ttl: entry.ttl,
                                        attr: entry.attr,
                                    }),
                                }
                            }
                        };
                        // create directory here
                        child.lock().await.replace(ri);
                    }
                    None => {
                        error!(
                            "BUG: parent {} has no upper inode after create_upper_dir",
                            pnode.inode
                        );
                        return Err(Error::from_raw_os_error(libc::EINVAL));
                    }
                }
                Ok(false)
            })
            .await?;

        if let Some(ri) = child.lock().await.take() {
            // Push the new real inode to the front of vector.
            self.add_upper_inode(ri, false).await;
        }

        Ok(())
    }

    // Add new upper RealInode to OverlayInode, clear all lower RealInodes if 'clear_lowers' is true.
    async fn add_upper_inode(self: &Arc<Self>, ri: RealInode<L>, clear_lowers: bool) {
        let mut inodes = self.real_inodes.lock().await;
        // Update self according to upper attribute.
        self.whiteout.store(ri.whiteout, Ordering::Relaxed);

        // Push the new real inode to the front of vector.
        let mut new = vec![Arc::new(ri)];
        // Drain lower RealInodes.
        let lowers = inodes.drain(..).collect::<Vec<Arc<RealInode<L>>>>();
        if !clear_lowers {
            // If not clear lowers, append them to the end of vector.
            new.extend(lowers);
        }
        inodes.extend(new);
    }

    // return the uppder layer fs.
    pub async fn in_upper_layer(&self) -> bool {
        let all_inodes = self.real_inodes.lock().await;
        let first = all_inodes.first();
        match first {
            Some(v) => v.in_upper_layer,
            None => false,
        }
    }

    pub async fn upper_layer_only(&self) -> bool {
        let real_inodes = self.real_inodes.lock().await;
        let first = real_inodes.first();
        match first {
            Some(v) => {
                if !v.in_upper_layer {
                    false
                } else {
                    real_inodes.len() == 1
                }
            }
            None => false,
        }
    }

    pub async fn first_layer_inode(&self) -> (Arc<L>, bool, u64) {
        let all_inodes = self.real_inodes.lock().await;
        let first = all_inodes.first();
        match first {
            Some(v) => (v.layer.clone(), v.in_upper_layer, v.inode),
            None => panic!("BUG: dangling OverlayInode"),
        }
    }

    pub async fn child(&self, name: &str) -> Option<Arc<OverlayInode<L>>> {
        self.childrens.lock().await.get(name).cloned()
    }

    pub async fn remove_child(&self, name: &str) -> Option<Arc<OverlayInode<L>>> {
        self.childrens.lock().await.remove(name)
    }

    pub async fn insert_child(&self, name: &str, node: Arc<OverlayInode<L>>) {
        self.childrens.lock().await.insert(name.to_string(), node);
    }

    /// Handles operations on the upper layer inode of an `OverlayInode` in a thread-safe manner.
    ///
    /// This function locks the `real_inodes` field of the `OverlayInode` and retrieves the first
    /// real inode (if any). If the first inode exists and belongs to the upper layer (`in_upper_layer` is true),
    /// the provided callback `f` is invoked with the inode wrapped in `Some`. Otherwise, `f` is invoked with `None`.
    ///
    /// # Arguments
    /// * `f`: A closure that takes an `Option<RealInode<L>>` and returns a future. The future resolves to a `Result<bool>`.
    ///
    /// # Returns
    /// * `Ok(bool)`: The result of invoking the callback `f`.
    /// * `Err(Erron)`: An error is returned if:
    ///   - There are no backend inodes (`real_inodes` is empty), indicating a dangling `OverlayInode`.
    ///   - The callback `f` itself returns an error.
    ///
    /// # Behavior
    /// 1. Locks the `real_inodes` field to ensure thread safety.
    /// 2. Checks if the first inode exists:
    ///    - If it exists and is in the upper layer, invokes `f(Some(inode))`.
    ///    - If it exists but is not in the upper layer, invokes `f(None)`.
    /// 3. If no inodes exist, returns an error indicating a dangling `OverlayInode`.
    ///
    /// # Example Use Case
    /// This function is typically used to perform operations on the upper layer inode of an `OverlayInode`,
    /// such as creating, modifying, or deleting files/directories in the overlay filesystem's upper layer.
    pub async fn handle_upper_inode_locked<F, Fut>(&self, f: F) -> Result<bool>
    where
        // Can pass a &RealInode (or None) to f for any lifetime 'a
        F: FnOnce(Option<Arc<RealInode<L>>>) -> Fut,
        // f returns a Future that must live at least as long as 'a
        Fut: Future<Output = Result<bool>>,
    {
        let all_inodes = self.real_inodes.lock().await;
        let first = all_inodes.first();
        match first {
            Some(v) => {
                if v.in_upper_layer {
                    f(Some(v.clone())).await
                } else {
                    f(None).await
                }
            }
            None => Err(Error::other(format!(
                "BUG: dangling OverlayInode {} without any backend inode",
                self.inode
            ))),
        }
    }
}
#[allow(unused)]
fn entry_type_from_mode(mode: libc::mode_t) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFBLK => libc::DT_BLK,
        libc::S_IFCHR => libc::DT_CHR,
        libc::S_IFDIR => libc::DT_DIR,
        libc::S_IFIFO => libc::DT_FIFO,
        libc::S_IFLNK => libc::DT_LNK,
        libc::S_IFREG => libc::DT_REG,
        libc::S_IFSOCK => libc::DT_SOCK,
        _ => libc::DT_UNKNOWN,
    }
}
impl<L: Layer + Send + Sync + 'static> OverlayFs<L> {
    pub fn new(
        upper: Option<Arc<L>>,
        lowers: Vec<Arc<L>>,
        params: Config,
        root_inode: u64,
    ) -> Result<Self> {
        // load root inode
        Ok(OverlayFs {
            config: params,
            lower_layers: lowers,
            upper_layer: upper,
            inodes: RwLock::new(InodeStore::new()),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            writeback: AtomicBool::new(false),
            no_open: AtomicBool::new(false),
            no_opendir: AtomicBool::new(false),
            killpriv_v2: AtomicBool::new(false),
            perfile_dax: AtomicBool::new(false),
            root_inodes: root_inode,
        })
    }

    pub fn root_inode(&self) -> Inode {
        self.root_inodes
    }

    async fn alloc_inode(&self, path: &str) -> Result<u64> {
        self.inodes.write().await.alloc_inode(path)
    }

    /// Add a file layer and stack and merge the previous file layers.
    pub async fn push_layer(&mut self, layer: Arc<L>) -> Result<()> {
        let upper = self.upper_layer.take();
        if let Some(upper) = upper {
            self.lower_layers.push(upper);
        }
        self.upper_layer = Some(layer);
        // TODO: merge previous file layers. need optimization
        self.import().await?;
        Ok(())
    }

    pub async fn import(&self) -> Result<()> {
        let mut root = OverlayInode::new();
        root.inode = self.root_inode();
        root.path = String::from("").into();
        root.name = String::from("").into();
        root.lookups = AtomicU64::new(2);
        root.real_inodes = Mutex::new(vec![]);
        let ctx = Request::default();

        // Update upper inode
        if let Some(layer) = self.upper_layer.as_ref() {
            let ino = layer.root_inode();
            let real = RealInode::new(
                layer.clone(),
                true,
                ino,
                false,
                false,
            )
            .await;
            root.real_inodes.lock().await.push(real.into());
        }

        // Update lower inodes.
        for layer in self.lower_layers.iter() {
            let ino = layer.root_inode();
            let real: RealInode<L> = RealInode::new(
                layer.clone(),
                false,
                ino,
                false,
                false,
            )
            .await;
            root.real_inodes.lock().await.push(real.into());
        }
        let root_node = Arc::new(root);

        // insert root inode into hash
        self.insert_inode(self.root_inode(), Arc::clone(&root_node))
            .await;

        info!("loading root directory");
        self.load_directory(ctx, &root_node).await?;
        info!("loaded root directory");

        Ok(())
    }

    async fn root_node(&self) -> Arc<OverlayInode<L>> {
        // Root node must exist.
        self.get_active_inode(self.root_inode()).await.unwrap()
    }

    async fn insert_inode(&self, inode: u64, node: Arc<OverlayInode<L>>) {
        self.inodes.write().await.insert_inode(inode, node).await;
    }

    async fn get_active_inode(&self, inode: u64) -> Option<Arc<OverlayInode<L>>> {
        self.inodes.read().await.get_inode(inode)
    }

    // Get inode which is active or deleted.
    async fn get_all_inode(&self, inode: u64) -> Option<Arc<OverlayInode<L>>> {
        let inode_store = self.inodes.read().await;
        match inode_store.get_inode(inode) {
            Some(n) => Some(n),
            None => inode_store.get_deleted_inode(inode),
        }
    }

    // Return the inode only if it's permanently deleted from both self.inodes and self.deleted_inodes.
    async fn remove_inode(
        &self,
        inode: u64,
        path_removed: Option<String>,
    ) -> Option<Arc<OverlayInode<L>>> {
        self.inodes
            .write()
            .await
            .remove_inode(inode, path_removed)
            .await
    }

    // Lookup child OverlayInode with <name> under <parent> directory.
    // If name is empty, return parent itself.
    // Parent dir will be loaded, but returned OverlayInode won't.
    async fn lookup_node(
        &self,
        ctx: Request,
        parent: Inode,
        name: &str,
    ) -> Result<Arc<OverlayInode<L>>> {
        if name.contains(SLASH_ASCII) {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        // Parent inode is expected to be loaded before this function is called.
        // TODO: Is this correct?
        let pnode = match self.get_active_inode(parent).await {
            Some(v) => v,
            None => {
                match self.get_all_inode(parent).await {
                    Some(v) => {
                        trace!(
                            "overlayfs:mod.rs:1031:lookup_node: parent inode {parent} is deleted"
                        );
                        v
                    }
                    None => {
                        trace!(
                            "overlayfs:mod.rs:1034:lookup_node: parent inode {parent} not found"
                        );
                        // Parent inode is not found, return ENOENT.
                        return Err(Error::from_raw_os_error(libc::ENOENT));
                    }
                }
            }
        };

        // Parent is whiteout-ed, return ENOENT.
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let st = pnode.stat64(ctx).await?;
        if utils::is_dir(&st.attr.kind) && !pnode.loaded.load(Ordering::Relaxed) {
            // Parent is expected to be directory, load it first.
            self.load_directory(ctx, &pnode).await?;
        }

        // Current file or dir.
        if name.eq(".")  
            // Root directory has no parent.
            || (parent == self.root_inode() && name.eq("..")) 
            // Special convention: empty name indicates current dir.
            || name.is_empty()
        {
            return Ok(Arc::clone(&pnode));
        }

        match pnode.child(name).await {
            // Child is found.
            Some(v) => Ok(v),
            None => {
                trace!("lookup_node: child {name} not found");
                Err(Error::from_raw_os_error(libc::ENOENT))
            }
        }
    }

    async fn lookup_node_ignore_enoent(
        &self,
        ctx: Request,
        parent: u64,
        name: &str,
    ) -> Result<Option<Arc<OverlayInode<L>>>> {
        match self.lookup_node(ctx, parent, name).await {
            Ok(n) => Ok(Some(Arc::clone(&n))),
            Err(e) => {
                if let Some(raw_error) = e.raw_os_error()
                    && raw_error == libc::ENOENT
                {
                    return Ok(None);
                }
                Err(e)
            }
        }
    }

    // Load entries of the directory from all layers, if node is not directory, return directly.
    async fn load_directory(&self, ctx: Request, node: &Arc<OverlayInode<L>>) -> Result<()> {
        if node.loaded.load(Ordering::Relaxed) {
            return Ok(());
        }

        // We got all childrens without inode.
        // info!("before scan childrens, ctx: {:?}, node: {:?}", ctx, node.inode);
        let childrens = node.scan_childrens(ctx).await?;
        // info!("scanned children");

        // =============== Start Lock Area ===================
        // Lock OverlayFs inodes.
        let mut inode_store = self.inodes.write().await;
        // Lock the OverlayInode and its childrens.
        let mut node_children = node.childrens.lock().await;

        // Check again in case another 'load_directory' function call gets locks and want to do duplicated work.
        if node.loaded.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Now we have two locks' protection, Fs inodes lock and OverlayInode's childrens lock.
        // info!("before iter childrens");
        for mut child in childrens.into_iter() {
            // Allocate inode for each child.
            let ino = inode_store.alloc_inode(&child.path.read().await)?;

            let name = child.name.read().await.clone();
            child.inode = ino;
            // Create bi-directional link between parent and child.
            child.parent = Mutex::new(Arc::downgrade(node));

            let arc_child = Arc::new(child);
            node_children.insert(name, arc_child.clone());
            // Record overlay inode in whole OverlayFs.
            inode_store.insert_inode(ino, arc_child).await;
        }
        // info!("after iter childrens");

        node.loaded.store(true, Ordering::Relaxed);

        Ok(())
    }

    async fn forget_one(&self, inode: Inode, count: u64) {
        if inode == self.root_inode() || inode == 0 {
            return;
        }

        let v = match self.get_all_inode(inode).await {
            Some(n) => n,
            None => {
                trace!("forget unknown inode: {inode}");
                return;
            }
        };

        // Use fetch_update to atomically update lookups in a loop until it succeeds
        v.lookups
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                // If count is larger than current lookups, return 0
                // Otherwise subtract count from current lookups
                if current < count {
                    Some(0)
                } else {
                    Some(current - count)
                }
            })
            .expect("fetch_update failed");

        let lookups = v.lookups.load(Ordering::Relaxed);
        trace!(
            "forget inode: {}, name {}, lookups: {}",
            inode,
            v.name.read().await,
            lookups
        );
        if lookups == 0 {
            debug!(
                "inode is forgotten: {}, name {}",
                inode,
                v.name.read().await
            );
            let _ = self.remove_inode(inode, None).await;
            let parent = v.parent.lock().await;

            if let Some(p) = parent.upgrade() {
                // remove it from hashmap
                p.remove_child(&v.name.read().await).await;
            }
        }
    }

    async fn do_lookup(&self, ctx: Request, parent: Inode, name: &str) -> Result<ReplyEntry> {
        let node = self.lookup_node(ctx, parent, name).await?;
        debug!("do_lookup: {name:?}, found");

        if node.whiteout.load(Ordering::Relaxed) {
            eprintln!("Error: node.whiteout.load() called.");
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let mut st = node.stat64(ctx).await?;
        st.attr.ino = node.inode;
        if utils::is_dir(&st.attr.kind) && !node.loaded.load(Ordering::Relaxed) {
            self.load_directory(ctx, &node).await?;
        }

        // FIXME: can forget happen between found and increase reference counter?
        let tmp = node.lookups.fetch_add(1, Ordering::Relaxed);
        trace!("lookup count: {}", tmp + 1);
        Ok(ReplyEntry {
            ttl: st.ttl,
            attr: st.attr,
            generation: 0,
        })
    }

    async fn do_statvfs(&self, ctx: Request, inode: Inode) -> Result<ReplyStatFs> {
        match self.get_active_inode(inode).await {
            Some(ovi) => {
                let all_inodes = ovi.real_inodes.lock().await;
                let real_inode = all_inodes
                    .first()
                    .ok_or(Error::other("backend inode not found"))?;
                Ok(real_inode.layer.statfs(ctx, real_inode.inode).await?)
            }
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_readdir<'a>(
        &self,
        ctx: Request,
        inode: Inode,
        handle: u64,
        offset: u64,
    ) -> Result<
        impl futures_util::stream::Stream<Item = std::result::Result<DirectoryEntry, Errno>> + Send + 'a,
    > {
        // lookup the directory
        let ovl_inode = match self.handles.lock().await.get(&handle) {
            Some(dir) => dir.node.clone(),
            None => {
                // Try to get data with inode.
                let node = self.lookup_node(ctx, inode, ".").await?;

                let st = node.stat64(ctx).await?;
                if !utils::is_dir(&st.attr.kind) {
                    return Err(Error::from_raw_os_error(libc::ENOTDIR));
                }

                node.clone()
            }
        };
        self.load_directory(ctx, &ovl_inode).await?;
        let mut childrens = Vec::new();
        //add myself as "."
        childrens.push((".".to_string(), ovl_inode.clone()));

        //add parent
        let parent_node = match ovl_inode.parent.lock().await.upgrade() {
            Some(p) => p.clone(),
            None => self.root_node().await,
        };
        childrens.push(("..".to_string(), parent_node));

        for (name, child) in ovl_inode.childrens.lock().await.iter() {
            // skip whiteout node
            if child.whiteout.load(Ordering::Relaxed) {
                continue;
            }
            childrens.push((name.clone(), child.clone()));
        }

        if offset >= childrens.len() as u64 {
            return Ok(iter(vec![].into_iter()));
        }
        let mut d: Vec<std::result::Result<DirectoryEntry, Errno>> = Vec::new();

        for (index, (name, child)) in (0_u64..).zip(childrens.into_iter()) {
            // make struct DireEntry and Entry
            let st = child.stat64(ctx).await?;
            let dir_entry = DirectoryEntry {
                inode: child.inode,
                kind: st.attr.kind,
                name: name.into(),
                offset: (index + 1) as i64,
            };
            d.push(Ok(dir_entry));
        }

        Ok(iter(d.into_iter()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_readdirplus<'a>(
        &self,
        ctx: Request,
        inode: Inode,
        handle: u64,
        offset: u64,
    ) -> Result<
        impl futures_util::stream::Stream<Item = std::result::Result<DirectoryEntryPlus, Errno>>
        + Send
        + 'a,
    > {
        // lookup the directory
        let ovl_inode = match self.handles.lock().await.get(&handle) {
            Some(dir) => {
                trace!(
                    "do_readdirplus: handle {} found, inode {}",
                    handle, dir.node.inode
                );
                dir.node.clone()
            }
            None => {
                trace!("do_readdirplus: handle {handle} not found, lookup inode {inode}");
                // Try to get data with inode.
                let node = self.lookup_node(ctx, inode, ".").await?;

                let st = node.stat64(ctx).await?;
                if !utils::is_dir(&st.attr.kind) {
                    return Err(Error::from_raw_os_error(libc::ENOTDIR));
                }

                node.clone()
            }
        };
        self.load_directory(ctx, &ovl_inode).await?;

        let mut childrens = Vec::new();
        //add myself as "."
        childrens.push((".".to_string(), ovl_inode.clone()));

        //add parent
        let parent_node = match ovl_inode.parent.lock().await.upgrade() {
            Some(p) => p.clone(),
            None => self.root_node().await,
        };
        childrens.push(("..".to_string(), parent_node));

        for (name, child) in ovl_inode.childrens.lock().await.iter() {
            // skip whiteout node
            if child.whiteout.load(Ordering::Relaxed) {
                continue;
            }
            childrens.push((name.clone(), child.clone()));
        }

        if offset >= childrens.len() as u64 {
            return Ok(iter(vec![].into_iter()));
        }
        let mut d: Vec<std::result::Result<DirectoryEntryPlus, Errno>> = Vec::new();

        for (index, (name, child)) in (0_u64..).zip(childrens.into_iter()) {
            if index >= offset {
                // make struct DireEntry and Entry
                let mut st = child.stat64(ctx).await?;
                child.lookups.fetch_add(1, Ordering::Relaxed);
                st.attr.ino = child.inode;
                let dir_entry = DirectoryEntryPlus {
                    inode: child.inode,
                    generation: 0,
                    kind: st.attr.kind,
                    name: name.into(),
                    offset: (index + 1) as i64,
                    attr: st.attr,
                    entry_ttl: st.ttl,
                    attr_ttl: st.ttl,
                };
                d.push(Ok(dir_entry));
            }
        }

        Ok(iter(d.into_iter()))
    }

    async fn do_mkdir(
        &self,
        ctx: Request,
        parent_node: Arc<OverlayInode<L>>,
        name: &str,
        mode: u32,
        umask: u32,
    ) -> Result<()> {
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // Parent node was deleted.
        if parent_node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let mut delete_whiteout = false;
        let mut set_opaque = false;
        if let Some(n) = self
            .lookup_node_ignore_enoent(ctx, parent_node.inode, name)
            .await?
        {
            // Node with same name exists, let's check if it's whiteout.
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            if n.in_upper_layer().await {
                delete_whiteout = true;
            }

            // Set opaque if child dir has lower layers.
            if !n.upper_layer_only().await {
                set_opaque = true;
            }
        }

        // Copy parent node up if necessary.
        let pnode = self.copy_node_up(ctx, parent_node).await?;

        let path = format!("{}/{}", pnode.path.read().await, name);
        let path_ref = &path;
        let new_node = Arc::new(Mutex::new(None));
        pnode
            .handle_upper_inode_locked(&mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                let parent_real_inode = match parent_real_inode {
                    Some(inode) => inode,
                    None => {
                        error!("BUG: parent doesn't have upper inode after copied up");
                        return Err(Error::from_raw_os_error(libc::EINVAL));
                    }
                };
                let osstr = OsStr::new(name);
                if delete_whiteout {
                    let _ = parent_real_inode
                        .layer
                        .delete_whiteout(ctx, parent_real_inode.inode, osstr)
                        .await;
                }

                // Allocate inode number.
                let ino = self.alloc_inode(path_ref).await?;
                let child_dir = parent_real_inode.mkdir(ctx, name, mode, umask).await?;
                // Set opaque if child dir has lower layers.
                if set_opaque {
                    parent_real_inode
                        .layer
                        .set_opaque(ctx, child_dir.inode)
                        .await?;
                }
                let ovi =
                    OverlayInode::new_from_real_inode(name, ino, path_ref.clone(), child_dir).await;
                new_node.lock().await.replace(ovi);
                Ok(false)
            })
            .await?;

        // new_node is always 'Some'
        let nn = new_node.lock().await.take();
        let arc_node = Arc::new(nn.unwrap());
        self.insert_inode(arc_node.inode, arc_node.clone()).await;
        pnode.insert_child(name, arc_node).await;
        Ok(())
    }

    async fn do_mknod(
        &self,
        ctx: Request,
        parent_node: &Arc<OverlayInode<L>>,
        name: &str,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> Result<()> {
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // Parent node was deleted.
        if parent_node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        match self
            .lookup_node_ignore_enoent(ctx, parent_node.inode, name)
            .await?
        {
            Some(n) => {
                // Node with same name exists, let's check if it's whiteout.
                if !n.whiteout.load(Ordering::Relaxed) {
                    return Err(Error::from_raw_os_error(libc::EEXIST));
                }

                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };
                            let osstr = OsStr::new(name);
                            if n.in_upper_layer().await {
                                let _ = parent_real_inode
                                    .layer
                                    .delete_whiteout(ctx, parent_real_inode.inode, osstr)
                                    .await;
                            }

                            let child_ri = parent_real_inode
                                .mknod(ctx, name, mode, rdev, umask)
                                .await?;

                            // Replace existing real inodes with new one.
                            n.add_upper_inode(child_ri, true).await;
                            Ok(false)
                        },
                    )
                    .await?;
            }
            None => {
                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                let new_node = Arc::new(Mutex::new(None));
                let path = format!("{}/{}", pnode.path.read().await, name);
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };

                            // Allocate inode number.
                            let ino = self.alloc_inode(&path).await?;
                            let child_ri = parent_real_inode
                                .mknod(ctx, name, mode, rdev, umask)
                                .await?;
                            let ovi = OverlayInode::new_from_real_inode(
                                name,
                                ino,
                                path.clone(),
                                child_ri,
                            )
                            .await;

                            new_node.lock().await.replace(ovi);
                            Ok(false)
                        },
                    )
                    .await?;

                let nn = new_node.lock().await.take();
                let arc_node = Arc::new(nn.unwrap());
                self.insert_inode(arc_node.inode, arc_node.clone()).await;
                pnode.insert_child(name, arc_node).await;
            }
        }

        Ok(())
    }

    async fn do_create(
        &self,
        ctx: Request,
        parent_node: &Arc<OverlayInode<L>>,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<Option<u64>> {
        let name_str = name.to_str().unwrap();
        let upper = self
            .upper_layer
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        // Parent node was deleted.
        if parent_node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let handle: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let real_ino: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let new_ovi = match self
            .lookup_node_ignore_enoent(ctx, parent_node.inode, name_str)
            .await?
        {
            Some(n) => {
                // Node with same name exists, let's check if it's whiteout.
                if !n.whiteout.load(Ordering::Relaxed) {
                    return Err(Error::from_raw_os_error(libc::EEXIST));
                }

                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };

                            if n.in_upper_layer().await {
                                let _ = parent_real_inode
                                    .layer
                                    .delete_whiteout(ctx, parent_real_inode.inode, name)
                                    .await;
                            }

                            let (child_ri, hd) =
                                parent_real_inode.create(ctx, name_str, mode, flags).await?;
                            real_ino.lock().await.replace(child_ri.inode);
                            handle.lock().await.replace(hd.unwrap());

                            // Replace existing real inodes with new one.
                            n.add_upper_inode(child_ri, true).await;
                            Ok(false)
                        },
                    )
                    .await?;
                n.clone()
            }
            None => {
                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                let new_node = Arc::new(Mutex::new(None));
                let path = format!("{}/{}", pnode.path.read().await, name_str);
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };

                            let (child_ri, hd) =
                                parent_real_inode.create(ctx, name_str, mode, flags).await?;
                            real_ino.lock().await.replace(child_ri.inode);
                            handle.lock().await.replace(hd.unwrap());
                            // Allocate inode number.
                            let ino = self.alloc_inode(&path).await?;
                            let ovi = OverlayInode::new_from_real_inode(
                                name_str,
                                ino,
                                path.clone(),
                                child_ri,
                            )
                            .await;

                            new_node.lock().await.replace(ovi);
                            Ok(false)
                        },
                    )
                    .await?;

                // new_node is always 'Some'
                let nn = new_node.lock().await.take();
                let arc_node = Arc::new(nn.unwrap());
                self.insert_inode(arc_node.inode, arc_node.clone()).await;
                pnode.insert_child(name_str, arc_node.clone()).await;
                arc_node
            }
        };

        let final_handle = match *handle.lock().await {
            Some(hd) => {
                if self.no_open.load(Ordering::Relaxed) {
                    None
                } else {
                    let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                    let handle_data = HandleData {
                        node: new_ovi,
                        real_handle: Some(RealHandle {
                            layer: upper.clone(),
                            in_upper_layer: true,
                            inode: real_ino.lock().await.unwrap(),
                            handle: AtomicU64::new(hd),
                        }),
                    };
                    self.handles
                        .lock()
                        .await
                        .insert(handle, Arc::new(handle_data));
                    Some(handle)
                }
            }
            None => None,
        };
        Ok(final_handle)
    }

    async fn do_rename(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        new_parent: Inode,
        new_name: &OsStr,
    ) -> Result<()> {
        let name_str = name.to_str().unwrap();
        let new_name_str = new_name.to_str().unwrap();

        let parent_node = self.lookup_node(req, parent, "").await?;
        let new_parent_node = self.lookup_node(req, new_parent, "").await?;
        let src_node = self.lookup_node(req, parent, name_str).await?;
        let dest_node_opt = self
            .lookup_node_ignore_enoent(req, new_parent, new_name_str)
            .await?;
        // trace!("parent_node: {}, new_parent_node: {}, src_node: {}, dest_node_opt: {:?}", parent_node.inode, new_parent_node.inode, src_node.inode, dest_node_opt.as_ref().map(|n| n.inode));

        if let Some(dest_node) = &dest_node_opt {
            let src_is_dir = src_node.is_dir(req).await?;
            let dest_is_dir = dest_node.is_dir(req).await?;
            if src_is_dir != dest_is_dir {
                return Err(Error::from_raw_os_error(libc::EISDIR));
            }
            if dest_is_dir {
                self.copy_directory_up(req, dest_node.clone()).await?;
                let (count, _) = dest_node.count_entries_and_whiteout(req).await?;
                if count > 0 {
                    return Err(Error::from_raw_os_error(libc::ENOTEMPTY));
                }
            }
        }

        let pnode = self.copy_node_up(req, parent_node).await?;
        let new_pnode = self.copy_node_up(req, new_parent_node).await?;
        let s_node = self.copy_node_up(req, src_node).await?;

        let need_whiteout = !s_node.upper_layer_only().await;

        let (p_layer, _, p_inode) = pnode.first_layer_inode().await;
        let (new_p_layer, _, new_p_inode) = new_pnode.first_layer_inode().await;
        assert!(Arc::ptr_eq(&p_layer, &new_p_layer));

        p_layer
            .rename(req, p_inode, name, new_p_inode, new_name)
            .await?;

        // Handle the replaced destination node (if any).
        if let Some(dest_node) = dest_node_opt {
            let path = dest_node.path.read().await.clone();
            self.remove_inode(dest_node.inode, Some(path)).await;
        }

        // Update the moved source node's state.

        // Remove from old parent.
        pnode.remove_child(name_str).await;
        self.remove_inode(s_node.inode, s_node.path.read().await.clone().into())
            .await;
        let new_path = format!("{}/{}", new_pnode.path.read().await, new_name_str);
        *s_node.path.write().await = new_path;
        *s_node.name.write().await = new_name_str.to_string();
        *s_node.parent.lock().await = Arc::downgrade(&new_pnode);
        new_pnode.insert_child(new_name_str, s_node.clone()).await;
        self.insert_inode(s_node.inode, s_node).await;

        // Create whiteout at the old location if necessary.
        if need_whiteout {
            p_layer.create_whiteout(req, p_inode, name).await?;
        }

        Ok(())
    }

    async fn do_link(
        &self,
        ctx: Request,
        src_node: &Arc<OverlayInode<L>>,
        new_parent: &Arc<OverlayInode<L>>,
        name: &str,
    ) -> Result<()> {
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // Node is whiteout.
        if src_node.whiteout.load(Ordering::Relaxed) || new_parent.whiteout.load(Ordering::Relaxed)
        {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let st = src_node.stat64(ctx).await?;
        if utils::is_dir(&st.attr.kind) {
            // Directory can't be hardlinked.
            return Err(Error::from_raw_os_error(libc::EPERM));
        }

        let src_node = self.copy_node_up(ctx, Arc::clone(src_node)).await?;
        let new_parent = self.copy_node_up(ctx, Arc::clone(new_parent)).await?;
        let src_ino = src_node.first_layer_inode().await.2;

        if let Some(existing_node) = self
            .lookup_node_ignore_enoent(ctx, new_parent.inode, name)
            .await?
        {
            // If it's not a whiteout, it's an error
            if !existing_node.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }
            // If it is a whiteout, we will overwrite it.
            // First, remove the physical whiteout file in the upper layer.
            new_parent
                .handle_upper_inode_locked(&mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                    let parent_ri = parent_real_inode.ok_or_else(|| {
                        error!("BUG: parent doesn't have upper inode after copied up");
                        Error::from_raw_os_error(libc::EINVAL)
                    })?;
                    // Only delete if the whiteout is in the upper layer
                    if existing_node.in_upper_layer().await {
                        let _ = parent_ri
                            .layer
                            .delete_whiteout(ctx, parent_ri.inode, OsStr::new(name))
                            .await;
                    }
                    Ok(false)
                })
                .await?;
        }

        new_parent
            .handle_upper_inode_locked(&mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                let parent_real_inode = match parent_real_inode {
                    Some(inode) => inode,
                    None => {
                        error!("BUG: parent doesn't have upper inode after copied up");
                        return Err(Error::from_raw_os_error(libc::EINVAL));
                    }
                };

                parent_real_inode.link(ctx, src_ino, name).await?;

                Ok(false)
            })
            .await?;

        self.insert_inode(src_node.inode, src_node.clone()).await;
        new_parent.insert_child(name, src_node).await;

        Ok(())
    }

    async fn do_symlink(
        &self,
        ctx: Request,
        linkname: &str,
        parent_node: &Arc<OverlayInode<L>>,
        name: &str,
    ) -> Result<()> {
        let name_os = OsStr::new(name);
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // parent was deleted.
        if parent_node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        match self
            .lookup_node_ignore_enoent(ctx, parent_node.inode, name)
            .await?
        {
            Some(n) => {
                // Node with same name exists, let's check if it's whiteout.
                if !n.whiteout.load(Ordering::Relaxed) {
                    return Err(Error::from_raw_os_error(libc::EEXIST));
                }

                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };

                            if n.in_upper_layer().await {
                                let _ = parent_real_inode
                                    .layer
                                    .delete_whiteout(ctx, parent_real_inode.inode, name_os)
                                    .await;
                            }

                            let child_ri = parent_real_inode.symlink(ctx, linkname, name).await?;

                            // Replace existing real inodes with new one.
                            n.add_upper_inode(child_ri, true).await;
                            Ok(false)
                        },
                    )
                    .await?;
            }
            None => {
                // Copy parent node up if necessary.
                let pnode = self.copy_node_up(ctx, Arc::clone(parent_node)).await?;
                let new_node: Arc<Mutex<Option<OverlayInode<L>>>> = Arc::new(Mutex::new(None));
                let path = format!("{}/{}", pnode.path.read().await, name);
                pnode
                    .handle_upper_inode_locked(
                        &mut |parent_real_inode: Option<Arc<RealInode<L>>>| async {
                            let parent_real_inode = match parent_real_inode {
                                Some(inode) => inode,
                                None => {
                                    error!("BUG: parent doesn't have upper inode after copied up");
                                    return Err(Error::from_raw_os_error(libc::EINVAL));
                                }
                            };

                            // Allocate inode number.
                            let ino = self.alloc_inode(&path).await?;
                            let child_ri = parent_real_inode.symlink(ctx, linkname, name).await?;
                            let ovi = OverlayInode::new_from_real_inode(
                                name,
                                ino,
                                path.clone(),
                                child_ri,
                            )
                            .await;

                            new_node.lock().await.replace(ovi);
                            Ok(false)
                        },
                    )
                    .await?;

                // new_node is always 'Some'
                let arc_node = Arc::new(new_node.lock().await.take().unwrap());
                self.insert_inode(arc_node.inode, arc_node.clone()).await;
                pnode.insert_child(name, arc_node).await;
            }
        }

        Ok(())
    }

    /// Copies a symbolic link from a lower layer to the upper layer.
    ///
    /// This function is a part of the copy-up process, triggered when a symlink that
    /// only exists in a lower layer is modified. It reads the link target and attributes
    /// from the lower layer and creates an identical symlink in the upper layer, crucially
    /// preserving the original host UID and GID.
    async fn copy_symlink_up(
        &self,
        ctx: Request,
        node: Arc<OverlayInode<L>>,
    ) -> Result<Arc<OverlayInode<L>>> {
        if node.in_upper_layer().await {
            return Ok(node);
        }

        let parent_node = if let Some(ref n) = node.parent.lock().await.upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::other("no parent?"));
        };

        // To preserve original ownership, we must get the raw, unmapped host attributes.
        // We achieve this by calling `getattr_helper`, which is specifically designed
        // to bypass the ID mapping logic. This is safe and does not affect other
        // functionalities because `getattr_helper` and the standard `stat64()` call
        // both rely on the same underlying `stat` system call; they only differ in
        // whether the resulting `uid` and `gid` are mapped.
        let (self_layer, _, self_inode) = node.first_layer_inode().await;
        let re = self_layer.getattr_helper(self_inode, None).await?;
        let st = ReplyAttr {
            ttl: re.1,
            attr: convert_stat64_to_file_attr(re.0),
        };

        if !parent_node.in_upper_layer().await {
            parent_node.clone().create_upper_dir(ctx, None).await?;
        }

        // Read the linkname from lower layer.
        let reply_data = self_layer.readlink(ctx, self_inode).await?;
        // Convert path to &str.
        let path = std::str::from_utf8(&reply_data.data)
            .map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;

        let new_upper_real: Arc<Mutex<Option<RealInode<L>>>> = Arc::new(Mutex::new(None));
        parent_node
            .handle_upper_inode_locked(&mut |parent_upper_inode: Option<Arc<RealInode<L>>>| async {
                // We already create upper dir for parent_node above.
                let parent_real_inode =
                    parent_upper_inode.ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;
                // We manually unfold the `symlink` logic here instead of calling the `symlink` method directly.
                // This is necessary to preserve the original file's UID and GID during the copy-up process.
                if !parent_real_inode.in_upper_layer {
                    return Err(Error::from_raw_os_error(libc::EROFS));
                }
                let link_name = OsStr::new(path);
                let filename = node.name.read().await;
                let filename = OsStr::new(filename.as_str());
                let entry = parent_real_inode
                    .layer
                    .symlink_helper(
                        ctx,
                        parent_real_inode.inode,
                        filename,
                        link_name,
                        st.attr.uid,
                        st.attr.gid,
                    )
                    .await?;
                let ri = RealInode {
                    layer: parent_real_inode.layer.clone(),
                    in_upper_layer: true,
                    inode: entry.attr.ino,
                    whiteout: false,
                    opaque: false,
                    stat: Some(ReplyAttr {
                        ttl: entry.ttl,
                        attr: entry.attr,
                    }),
                };
                new_upper_real.lock().await.replace(ri);
                Ok(false)
            })
            .await?;

        if let Some(real_inode) = new_upper_real.lock().await.take() {
            // update upper_inode and first_inode()
            node.add_upper_inode(real_inode, true).await;
        }

        Ok(node)
    }

    /// Copies a regular file and its contents from a lower layer to the upper layer.
    ///
    /// This function is a core part of the copy-up process, triggered when a regular file
    /// that only exists in a lower layer is written to. It creates an empty file in the
    /// upper layer with the original file's attributes (mode, UID, GID), and then copies
    /// the entire content from the lower layer file to the new upper layer file.
    async fn copy_regfile_up(
        &self,
        ctx: Request,
        node: Arc<OverlayInode<L>>,
    ) -> Result<Arc<OverlayInode<L>>> {
        if node.in_upper_layer().await {
            return Ok(node);
        }

        let parent_node = if let Some(ref n) = node.parent.lock().await.upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::other("no parent?"));
        };

        // To preserve original ownership, we must get the raw, unmapped host attributes.
        // We achieve this by calling `getattr_helper`, which is specifically designed
        // to bypass the ID mapping logic. This is safe and does not affect other
        // functionalities because `getattr_helper` and the standard `stat64()` call
        // both rely on the same underlying `stat` system call; they only differ in
        // whether the resulting `uid` and `gid` are mapped.
        let (lower_layer, _, lower_inode) = node.first_layer_inode().await;
        let re = lower_layer.getattr_helper(lower_inode, None).await?;
        let st = ReplyAttr {
            ttl: re.1,
            attr: convert_stat64_to_file_attr(re.0),
        };
        trace!(
            "copy_regfile_up: node {} in lower layer's inode {}",
            node.inode, lower_inode
        );

        if !parent_node.in_upper_layer().await {
            parent_node.clone().create_upper_dir(ctx, None).await?;
        }

        // create the file in upper layer using information from lower layer

        let flags = libc::O_WRONLY;
        let mode = mode_from_kind_and_perm(st.attr.kind, st.attr.perm);

        let upper_handle = Arc::new(Mutex::new(0));
        let upper_real_inode = Arc::new(Mutex::new(None));
        parent_node
            .handle_upper_inode_locked(&mut |parent_upper_inode: Option<Arc<RealInode<L>>>| async {
                // We already create upper dir for parent_node.
                let parent_real_inode = parent_upper_inode.ok_or_else(|| {
                    error!("parent {} has no upper inode", parent_node.inode);
                    Error::from_raw_os_error(libc::EINVAL)
                })?;
                // We manually unfold the `create` logic here instead of calling the `create` method directly.
                // This is necessary to preserve the original file's UID and GID during the copy-up process.
                if !parent_real_inode.in_upper_layer {
                    return Err(Error::from_raw_os_error(libc::EROFS));
                }
                let name = node.name.read().await;
                let name = OsStr::new(name.as_str());
                let create_rep = parent_real_inode
                    .layer
                    .create_helper(
                        ctx,
                        parent_real_inode.inode,
                        name,
                        mode,
                        flags.try_into().unwrap(),
                        st.attr.uid,
                        st.attr.gid,
                    )
                    .await?;

                let (inode, h) = (
                    RealInode {
                        layer: parent_real_inode.layer.clone(),
                        in_upper_layer: true,
                        inode: create_rep.attr.ino,
                        whiteout: false,
                        opaque: false,
                        stat: Some(ReplyAttr {
                            ttl: create_rep.ttl,
                            attr: create_rep.attr,
                        }),
                    },
                    Some(create_rep.fh),
                );
                trace!(
                    "copy_regfile_up: created upper file {name:?} with inode {}",
                    inode.inode
                );
                *upper_handle.lock().await = h.unwrap_or(0);
                upper_real_inode.lock().await.replace(inode);
                Ok(false)
            })
            .await?;

        let rep = lower_layer
            .open(ctx, lower_inode, libc::O_RDONLY as u32)
            .await?;

        let lower_handle = rep.fh;

        // need to use work directory and then rename file to
        // final destination for atomic reasons.. not deal with it for now,
        // use stupid copy at present.
        // FIXME: this need a lot of work here, ntimes, xattr, etc.

        // Copy from lower real inode to upper real inode.
        // TODO: use sendfile here.

        let u_handle = *upper_handle.lock().await;
        let ri = upper_real_inode.lock().await.take();
        if let Some(ri) = ri {
            let mut offset: usize = 0;
            let size = 4 * 1024 * 1024;

            loop {
                let ret = lower_layer
                    .read(ctx, lower_inode, lower_handle, offset as u64, size)
                    .await?;

                let len = ret.data.len();
                if len == 0 {
                    break;
                }

                let ret = ri
                    .layer
                    .write(ctx, ri.inode, u_handle, offset as u64, &ret.data, 0, 0)
                    .await?;

                assert_eq!(ret.written as usize, len);
                offset += ret.written as usize;
            }

            if let Err(e) = ri.layer.release(ctx, ri.inode, u_handle, 0, 0, true).await {
                let e: std::io::Error = e.into();
                // Ignore ENOSYS.
                if e.raw_os_error() != Some(libc::ENOSYS) {
                    return Err(e);
                }
            }
            node.add_upper_inode(ri, true).await;
        } else {
            error!("BUG: upper real inode is None after copy up");
        }

        lower_layer
            .release(ctx, lower_inode, lower_handle, 0, 0, true)
            .await?;

        Ok(Arc::clone(&node))
    }

    /// Copies the specified node to the upper layer of the filesystem
    ///
    /// Performs different operations based on the node type:
    /// - **Directory**: Creates a corresponding directory in the upper layer
    /// - **Symbolic link**: Recursively copies to the upper layer
    /// - **Regular file**: Copies file content to the upper layer
    ///
    /// # Parameters
    /// * `ctx`: FUSE request context
    /// * `node`: Reference to the node to be copied
    ///
    /// # Returns
    /// Returns a reference to the upper-layer node on success, or an error on failure
    async fn copy_node_up(
        &self,
        ctx: Request,
        node: Arc<OverlayInode<L>>,
    ) -> Result<Arc<OverlayInode<L>>> {
        if node.in_upper_layer().await {
            return Ok(node);
        }

        let st = node.stat64(ctx).await?;
        match st.attr.kind {
            FileType::Directory => {
                node.clone().create_upper_dir(ctx, None).await?;
                Ok(node)
            }
            FileType::Symlink => {
                // For symlink.
                self.copy_symlink_up(ctx, node).await
            }
            FileType::RegularFile => {
                // For regular file.
                self.copy_regfile_up(ctx, node).await
            }
            _ => {
                // For other file types. return error.
                Err(Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    /// recursively copy directory and all its contents to upper layer
    async fn copy_directory_up(
        &self,
        ctx: Request,
        node: Arc<OverlayInode<L>>,
    ) -> Result<Arc<OverlayInode<L>>> {
        // Ensure the directory itself is copied up first
        self.copy_node_up(ctx, node.clone()).await?;

        // load directory to cache
        self.load_directory(ctx, &node).await?;

        // go through all children
        let children = node.childrens.lock().await.clone();
        for (_name, child) in children.iter() {
            if _name == "." || _name == ".." {
                continue;
            }
            // jump over whiteout
            if child.whiteout.load(Ordering::Relaxed) {
                continue;
            }
            let st = child.stat64(ctx).await?;
            if !child.in_upper_layer().await {
                match st.attr.kind {
                    FileType::Directory => {
                        // recursively copy subdirectory
                        Box::pin(self.copy_directory_up(ctx, child.clone())).await?;
                    }
                    FileType::Symlink | FileType::RegularFile => {
                        // copy node up symlink or regular file
                        Box::pin(self.copy_node_up(ctx, child.clone())).await?;
                    }
                    _ => {
                        // other file types are ignored
                    }
                }
            } else if utils::is_dir(&st.attr.kind) {
                // If it is already in the upper layer, but the directory is not loaded,
                // ensure that its contents are also copied up recursively.
                Box::pin(self.copy_directory_up(ctx, child.clone())).await?;
            }
        }

        Ok(node)
    }

    async fn do_rm(&self, ctx: Request, parent: u64, name: &OsStr, dir: bool) -> Result<()> {
        // 1. Read-only mount guard
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // 2. Locate the parent Overlay Inode.
        // Find parent Overlay Inode.
        let pnode = self.lookup_node(ctx, parent, "").await?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }
        let to_name = name.to_str().unwrap();

        // 3. Locate the child Overlay Inode for the given name
        // Find the Overlay Inode for child with <name>.
        let node = self.lookup_node(ctx, parent, to_name).await?;
        if node.whiteout.load(Ordering::Relaxed) {
            // already deleted.
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // 4. If removing a directory, ensure it is empty of real entries
        if dir {
            self.load_directory(ctx, &node).await?;
            let (count, whiteouts) = node.count_entries_and_whiteout(ctx).await?;
            trace!("entries: {count}, whiteouts: {whiteouts}\n");
            if count > 0 {
                return Err(Error::from_raw_os_error(libc::ENOTEMPTY));
            }

            // Delete all whiteouts.
            if whiteouts > 0 && node.in_upper_layer().await {
                self.empty_node_directory(ctx, Arc::clone(&node)).await?;
            }

            trace!("whiteouts deleted!\n");
        }

        // 5. Decide whether we need to create a whiteout entry
        // We'll filp this off if upper-layer unlink suffices or parent is opaque
        let need_whiteout = AtomicBool::new(true);
        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode)).await?;

        if node.upper_layer_only().await {
            need_whiteout.store(false, Ordering::Relaxed);
        }

        let mut df = |parent_upper_inode: Option<Arc<RealInode<L>>>| async {
            let parent_real_inode = parent_upper_inode.ok_or_else(|| {
                error!(
                    "BUG: parent {} has no upper inode after copy up",
                    pnode.inode
                );
                Error::from_raw_os_error(libc::EINVAL)
            })?;

            // Parent is opaque, it shadows everything in lower layers so no need to create extra whiteouts.
            if parent_real_inode.opaque {
                need_whiteout.store(false, Ordering::Relaxed);
            }
            if dir {
                parent_real_inode
                    .layer
                    .rmdir(ctx, parent_real_inode.inode, name)
                    .await?;
            } else {
                parent_real_inode
                    .layer
                    .unlink(ctx, parent_real_inode.inode, name)
                    .await?;
            }

            Ok(false)
        };

        // 6. Perform the unlink/rmdir operation and memory cleanup
        if node.in_upper_layer().await {
            pnode.handle_upper_inode_locked(&mut df).await?;
        }
        pnode.remove_child(name.to_str().unwrap()).await;
        let path = node.path.read().await.clone();
        self.remove_inode(node.inode, Some(path)).await;

        // 7. If needed, create a entry in the upper layer to mask lower-layer files
        if need_whiteout.load(Ordering::Relaxed) {
            trace!("do_rm: creating whiteout\n");
            // pnode is copied up, so it has upper layer.
            pnode
                .handle_upper_inode_locked(
                    &mut |parent_upper_inode: Option<Arc<RealInode<L>>>| async {
                        let parent_real_inode = parent_upper_inode.ok_or_else(|| {
                            error!(
                                "BUG: parent {} has no upper inode after copy up",
                                pnode.inode
                            );
                            Error::from_raw_os_error(libc::EINVAL)
                        })?;

                        let child_ri = parent_real_inode.create_whiteout(ctx, to_name).await?; //FIXME..............
                        let path = format!("{}/{}", pnode.path.read().await, to_name);
                        let ino: u64 = self.alloc_inode(&path).await?;
                        let ovi = Arc::new(
                            OverlayInode::new_from_real_inode(to_name, ino, path.clone(), child_ri)
                                .await,
                        );

                        self.insert_inode(ino, ovi.clone()).await;
                        pnode.insert_child(to_name, ovi.clone()).await;
                        Ok(false)
                    },
                )
                .await?;
        }

        Ok(())
    }

    async fn do_fsync(
        &self,
        ctx: Request,
        inode: Inode,
        datasync: bool,
        handle: Handle,
        syncdir: bool,
    ) -> Result<()> {
        // Use O_RDONLY flags which indicates no copy up.
        let data = self
            .get_data(ctx, Some(handle), inode, libc::O_RDONLY as u32)
            .await?;

        trace!("do_fsync: got data for handle: {handle}, inode:{inode}");

        match data.real_handle {
            // FIXME: need to test if inode matches corresponding handle?
            None => {
                trace!("do_fsync: no real handle found for handle: {handle}, inode:{inode}");
                Err(Error::from_raw_os_error(libc::ENOENT))
            }
            Some(ref rh) => {
                let real_handle = rh.handle.load(Ordering::Relaxed);
                // TODO: check if it's in upper layer? @weizhang555
                if syncdir {
                    trace!(
                        "do_fsync: layer.fsyncdir called for handle: {}, inode:{}; rh.inode: {}, real_handle: {}",
                        handle, inode, rh.inode, real_handle
                    );
                    rh.layer
                        .fsyncdir(ctx, rh.inode, real_handle, datasync)
                        .await
                        .map_err(|e| e.into())
                } else {
                    rh.layer
                        .fsync(ctx, rh.inode, real_handle, datasync)
                        .await
                        .map_err(|e| e.into())
                }
            }
        }
    }

    // Delete everything in the directory only on upper layer, ignore lower layers.
    async fn empty_node_directory(&self, ctx: Request, node: Arc<OverlayInode<L>>) -> Result<()> {
        let st = node.stat64(ctx).await?;
        if !utils::is_dir(&st.attr.kind) {
            // This function can only be called on directories.
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        let (layer, in_upper, inode) = node.first_layer_inode().await;
        if !in_upper {
            return Ok(());
        }

        // Copy node.childrens Hashmap to Vector, the Vector is also used as temp storage,
        // Without this, Rust won't allow us to remove them from node.childrens.
        let iter = node
            .childrens
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();

        for child in iter {
            // We only care about upper layer, ignore lower layers.
            if child.in_upper_layer().await {
                let child_name = child.name.read().await.clone();
                let child_name_os = OsStr::new(&child_name);
                if child.whiteout.load(Ordering::Relaxed) {
                    layer.delete_whiteout(ctx, inode, child_name_os).await?
                } else {
                    let s = child.stat64(ctx).await?;
                    let cname: &OsStr = OsStr::new(&child_name_os);
                    if utils::is_dir(&s.attr.kind) {
                        let (count, whiteouts) = child.count_entries_and_whiteout(ctx).await?;
                        if count + whiteouts > 0 {
                            let cb = child.clone();
                            Box::pin(async move { self.empty_node_directory(ctx, cb).await })
                                .await?;
                        }
                        layer.rmdir(ctx, inode, cname).await?
                    } else {
                        layer.unlink(ctx, inode, cname).await?;
                    }
                }

                let cpath = child.path.read().await.clone();
                // delete the child
                self.remove_inode(child.inode, Some(cpath)).await;
                node.remove_child(&child_name).await;
            }
        }

        Ok(())
    }

    async fn find_real_info_from_handle(
        &self,
        handle: Handle,
    ) -> Result<(Arc<L>, Inode, Handle)> {
        match self.handles.lock().await.get(&handle) {
            Some(h) => match h.real_handle {
                Some(ref rhd) => {
                    trace!(
                        "find_real_info_from_handle: layer in upper: {}",
                        rhd.in_upper_layer
                    );
                    Ok((
                        rhd.layer.clone(),
                        rhd.inode,
                        rhd.handle.load(Ordering::Relaxed),
                    ))
                }
                None => Err(Error::from_raw_os_error(libc::ENOENT)),
            },

            None => Err(Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    async fn find_real_inode(&self, inode: Inode) -> Result<(Arc<L>, Inode)> {
        if let Some(n) = self.get_active_inode(inode).await {
            let (first_layer, _, first_inode) = n.first_layer_inode().await;
            return Ok((first_layer, first_inode));
        } else if let Some(n) = self.get_all_inode(inode).await {
            trace!("find_real_inode: found inode by get_all_inode: {}", n.inode);
            let (first_layer, _, first_inode) = n.first_layer_inode().await;
            return Ok((first_layer, first_inode));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    async fn get_data(
        &self,
        ctx: Request,
        handle: Option<Handle>,
        inode: Inode,
        flags: u32,
    ) -> Result<Arc<HandleData<L>>> {
        let no_open = self.no_open.load(Ordering::Relaxed);
        if !no_open {
            if let Some(h) = handle
                && let Some(v) = self.handles.lock().await.get(&h)
                && v.node.inode == inode
            {
                // trace!("get_data: found handle");
                return Ok(Arc::clone(v));
            }
        } else {
            let readonly: bool = flags
                & (libc::O_APPEND | libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_WRONLY)
                    as u32
                == 0;

            // lookup node
            let node = self.lookup_node(ctx, inode, "").await?;

            // whiteout node
            if node.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::ENOENT));
            }

            if !readonly {
                // Check if upper layer exists, return EROFS is not exists.
                self.upper_layer
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;
                // copy up to upper layer
                self.copy_node_up(ctx, Arc::clone(&node)).await?;
            }

            let (layer, in_upper_layer, inode) = node.first_layer_inode().await;
            let handle_data = HandleData {
                node: Arc::clone(&node),
                real_handle: Some(RealHandle {
                    layer,
                    in_upper_layer,
                    inode,
                    handle: AtomicU64::new(0),
                }),
            };
            return Ok(Arc::new(handle_data));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    // extend or init the inodes number to one overlay if the current number is done.
    pub async fn extend_inode_alloc(&self, key: u64) {
        let next_inode = key * INODE_ALLOC_BATCH;
        let limit_inode = next_inode + INODE_ALLOC_BATCH - 1;
        self.inodes
            .write()
            .await
            .extend_inode_number(next_inode, limit_inode);
    }
}

/// Wrap the parameters for mounting overlay filesystem.
#[derive(Debug, Clone)]
pub struct OverlayArgs<P, Q, R, M, N, I>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
    R: AsRef<Path>,
    M: AsRef<str>,
    N: Into<String>,
    I: IntoIterator<Item = R>,
{
    pub mountpoint: P,
    pub upperdir: Q,
    pub lowerdir: I,
    pub privileged: bool,
    pub mapping: Option<M>,
    pub name: Option<N>,
    pub allow_other: bool,
}

/// Mounts the filesystem using the given parameters and returns the mount handle.
///
/// # Parameters
/// - `mountpoint`: Path to the mount point.
/// - `upperdir`: Path to the upper directory.
/// - `lowerdir`: Paths to the lower directories.
/// - `privileged`: If true, use privileged mount; otherwise, unprivileged mount.
/// - `mapping`: Optional user/group ID mapping for unprivileged mounts.
/// - `name`: Optional name for the filesystem.
/// - `allow_other`: If true, allows other users to access the filesystem.
///
/// # Returns
/// A mount handle on success.
pub async fn mount_fs<P, Q, R, M, N, I>(
    args: OverlayArgs<P, Q, R, M, N, I>,
) -> rfuse3::raw::MountHandle
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
    R: AsRef<Path>,
    M: AsRef<str>,
    N: Into<String>,
    I: IntoIterator<Item = R>,
{
    // Create lower layers
    let mut lower_layers = Vec::new();
    for lower in args.lowerdir {
        let layer = new_passthroughfs_layer(PassthroughArgs {
            root_dir: lower,
            mapping: args.mapping.as_ref().map(|m| m.as_ref()),
        })
        .await
        .expect("Failed to create lower filesystem layer");
        lower_layers.push(Arc::new(layer));
    }
    // Create upper layer
    let upper_layer = Arc::new(
        new_passthroughfs_layer(PassthroughArgs {
            root_dir: args.upperdir,
            mapping: args.mapping.as_ref().map(|m| m.as_ref()),
        })
        .await
        .expect("Failed to create upper filesystem layer"),
    );

    // Configure overlay filesystem
    let config = Config {
        mountpoint: args.mountpoint.as_ref().to_path_buf(),
        do_import: true,
        ..Default::default()
    };
    let overlayfs = OverlayFs::new(Some(upper_layer), lower_layers, config, 1)
        .expect("Failed to initialize OverlayFs");
    let logfs = LoggingFileSystem::new(overlayfs);

    let mount_path: OsString = OsString::from(args.mountpoint.as_ref().as_os_str());

    // Obtain the current user's uid and gid
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mut mount_options = MountOptions::default();
    mount_options
        .force_readdir_plus(true)
        .uid(uid)
        .gid(gid)
        .allow_other(args.allow_other);
    if let Some(name) = args.name {
        mount_options.fs_name(name);
    }

    // Mount filesystem based on privilege flag and return the mount handle
    if !args.privileged {
        debug!("Mounting with unprivileged mode");
        Session::new(mount_options)
            .mount_with_unprivileged(logfs, mount_path)
            .await
            .expect("Unprivileged mount failed")
    } else {
        debug!("Mounting with privileged mode");
        Session::new(mount_options)
            .mount(logfs, mount_path)
            .await
            .expect("Privileged mount failed")
    }
}
