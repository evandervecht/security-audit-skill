use std::path::{Path, PathBuf};

use actix_files::NamedFile;
use actix_web::{error, web, Result};

const UPLOAD_ROOT: &str = "./uploads";

// GET /download/{filename}
// Only a bare file name is accepted; the resolved path must stay in the root.
pub async fn download(path: web::Path<String>) -> Result<NamedFile> {
    let requested = path.into_inner();

    let name = Path::new(&requested)
        .file_name()
        .ok_or_else(|| error::ErrorBadRequest("invalid file name"))?;

    let full: PathBuf = Path::new(UPLOAD_ROOT).join(name);
    let canonical = full.canonicalize().map_err(error::ErrorNotFound)?;
    let root = Path::new(UPLOAD_ROOT)
        .canonicalize()
        .map_err(error::ErrorInternalServerError)?;
    if !canonical.starts_with(&root) {
        return Err(error::ErrorForbidden("path escapes upload root"));
    }

    let file = NamedFile::open(canonical)?;
    Ok(file)
}
