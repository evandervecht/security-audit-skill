# SA-GCP-01: Granular predefined role on project (SAFE)
resource "google_project_iam_member" "storage_admin" {
  project = "my-project"
  role    = "roles/storage.admin"
  member  = "user:admin@example.com"
}
