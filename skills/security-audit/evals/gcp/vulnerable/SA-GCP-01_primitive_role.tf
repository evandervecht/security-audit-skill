# SA-GCP-01: Primitive Owner role on project (VULNERABLE)
resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:admin@example.com"
}
