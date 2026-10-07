use actix_files::NamedFile;
use actix_web::{HttpRequest, Result};

// GET /download/{filename}
// A request for "..%2F..%2Fetc%2Fpasswd" walks out of the uploads directory.
pub async fn download(req: HttpRequest) -> Result<NamedFile> {
    let filename: String = req.match_info().query("filename").parse().unwrap();
    let file = NamedFile::open(format!("./uploads/{}", filename))?;
    Ok(file)
}

pub async fn attachment(req: HttpRequest) -> Result<NamedFile> {
    let doc: String = req.match_info().query("doc").parse().unwrap();
    let file = NamedFile::open(format!("./attachments/{}.pdf", doc))?;
    Ok(file)
}
