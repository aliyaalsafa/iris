//! A single zstd-compressed Parquet file.

use std::fs::File;
use std::sync::Arc;

use arrow::datatypes::{FieldRef, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};
use serde::Serialize;
use serde_arrow::schema::{SchemaLike, TracingOptions};

use super::out_path;

const ROW_GROUP_ROWS: usize = 1 << 17;
const ZSTD_LEVEL: i32 = 3;

/// Derive Arrow fields from a sample value's serde shape.
pub fn traced<T: Serialize>(sample: T) -> Vec<FieldRef> {
    Vec::<FieldRef>::from_samples(&[sample], TracingOptions::default())
        .expect("schema trace failed")
}

pub struct Sink {
    w: ArrowWriter<File>,
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
        let w = ArrowWriter::try_new(file, Arc::new(Schema::new(fields.to_vec())), Some(props))
            .unwrap_or_else(|e| panic!("init writer {}: {e}", path.display()));
        Self { w, fields, name }
    }

    /// Append rows; errors are logged, not propagated, so one bad batch can't stop the writer.
    pub fn write<T: Serialize>(&mut self, rows: &[T]) {
        let res = serde_arrow::to_record_batch(self.fields, &rows)
            .map_err(|e| e.to_string())
            .and_then(|b| self.w.write(&b).map_err(|e| e.to_string()));
        if let Err(e) = res {
            eprintln!("warning: writing {}: {e}", self.name);
        }
    }

    pub fn close(self) {
        if let Err(e) = self.w.close() {
            eprintln!("warning: closing {}: {e}", self.name);
        }
    }
}
