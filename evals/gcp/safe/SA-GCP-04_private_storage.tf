# SA-GCP-04: Private Cloud Storage bucket (SAFE)
resource "google_storage_bucket_iam_member" "app" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}
