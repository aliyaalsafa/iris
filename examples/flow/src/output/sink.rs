//! A single zstd-compressed Parquet file.
//!
//! On a network share (CIFS, NFS) `write` only fills the page cache; the data
//! reaches the server later. A failed writeback is reported only by
//! `fsync`/`close`, so `close` fsyncs and every file that failed is recorded
//! for the end-of-run report. Writes go through `AlignedWriter`, which avoids
//! the silent loss fsync cannot see (see aligned.rs).

use std::fs::File;
use std::sync::{Arc, Mutex};

use arrow::datatypes::{FieldRef, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};
use serde::Serialize;
use serde_arrow::schema::{SchemaLike, TracingOptions};

use super::aligned::AlignedWriter;
use super::out_path;

const ROW_GROUP_ROWS: usize = 1 << 17;
const ZSTD_LEVEL: i32 = 3;

/// "<file>: <error>" for every write, finalize or fsync that failed.
static FAILURES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_failure(name: &str, e: String) {
    eprintln!("ERROR: {name}.parquet: {e}");
    FAILURES.lock().unwrap().push(format!("{name}.parquet: {e}"));
}

/// Every failure recorded so far; empty if every file is intact on disk.
pub fn failures() -> Vec<String> {
    FAILURES.lock().unwrap().clone()
}

/// Derive Arrow fields from a sample value's serde shape.
pub fn traced<T: Serialize>(sample: T) -> Vec<FieldRef> {
    Vec::<FieldRef>::from_samples(&[sample], TracingOptions::default())
        .expect("schema trace failed")
}

pub struct Sink {
    w: ArrowWriter<AlignedWriter<File>>,
    fields: &'static [FieldRef],
    name: String,
}

impl Sink {
    /// Create `<out_dir>/<name>.parquet`. Panics if the file can't be created.
    pub fn open(name: String, fields: &'static [FieldRef]) -> Self {
        let path = out_path(&format!("{name}.parquet"));
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(ZSTD_LEVEL).unwrap()))
            .set_max_row_group_size(ROW_GROUP_ROWS)
            .set_writer_version(WriterVersion::PARQUET_2_0)
            .build();
        let file = File::create(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
        let file = AlignedWriter::new(file);
        let w = ArrowWriter::try_new(file, Arc::new(Schema::new(fields.to_vec())), Some(props))
            .unwrap_or_else(|e| panic!("init writer {}: {e}", path.display()));
        Self { w, fields, name }
    }

    /// Append rows; errors are recorded, not propagated, so one bad batch can't stop the writer.
    pub fn write<T: Serialize>(&mut self, rows: &[T]) {
        let res = serde_arrow::to_record_batch(self.fields, &rows)
            .map_err(|e| e.to_string())
            .and_then(|b| self.w.write(&b).map_err(|e| e.to_string()));
        if let Err(e) = res {
            record_failure(&self.name, format!("write: {e}"));
        }
    }

    /// Write the footer and the aligned writer's tail, then fsync: the only
    /// point at which a lost writeback on a network share is reported.
    /// Dropping the `File` instead would discard `close`'s error as well.
    pub fn close(self) {
        let name = self.name;
        let res = self
            .w
            .into_inner()
            .map_err(|e| format!("finalize: {e}"))
            .and_then(|a| a.finish().map_err(|e| format!("write tail: {e}")))
            .and_then(|f| f.sync_all().map_err(|e| format!("fsync: {e}")));
        if let Err(e) = res {
            record_failure(&name, e);
        }
    }
}
