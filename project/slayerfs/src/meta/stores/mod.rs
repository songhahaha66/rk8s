//! Metadata Store Implementations
//!
//! This module contains all concrete implementations of the MetaStore trait.
//! Each store provides a different backend for metadata persistence:
//!
//! - `DatabaseMetaStore`: SQL databases (PostgreSQL, SQLite)
//! - `EtcdMetaStore`: Distributed etcd cluster

pub mod database_store;
pub mod etcd_store;

// Re-export main types for convenience
pub use database_store::DatabaseMetaStore;
pub use etcd_store::EtcdMetaStore;
