# SA-GCP-03: allUsers IAM binding (VULNERABLE)
resource "google_project_iam_binding" "public" {
  project = "my-project"
  role    = "roles/viewer"
  members = ["allUsers"]
}
