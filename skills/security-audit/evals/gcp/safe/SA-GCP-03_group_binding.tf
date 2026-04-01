# SA-GCP-03: Restricted group IAM binding (SAFE)
resource "google_project_iam_binding" "team" {
  project = "my-project"
  role    = "roles/viewer"
  members = ["group:team@example.com"]
}
