# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# AegisOps Security, Secret Manager, DLP, Model Armor, and Optional Vertex AI Search IaC

variable "min_instances" {
  type        = number
  description = "Minimum warm Agent Runtime instances (0 keeps idle cost at $0)."
  default     = 0
}

variable "enable_cloud_dlp" {
  type        = bool
  description = "Enable Google Cloud DLP API redaction in production runtime."
  default     = true
}

variable "enable_vertex_search" {
  type        = bool
  description = "Provision an optional Vertex AI Search datastore for SRE runbooks."
  default     = false
}

locals {
  aegis_security_apis = [
    "secretmanager.googleapis.com",
    "dlp.googleapis.com",
    "modelarmor.googleapis.com",
    "discoveryengine.googleapis.com",
  ]

  aegis_extra_sa_roles = [
    "roles/dlp.user",
    "roles/modelarmor.user",
    "roles/discoveryengine.viewer",
  ]
}

resource "google_project_service" "aegis_security_services" {
  for_each           = toset(local.aegis_security_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Secret Manager shells (secret versions are populated out-of-band; NEVER stored in Git/Terraform)
resource "google_secret_manager_secret" "pagerduty_token" {
  project   = var.project_id
  secret_id = "${var.project_name}-pagerduty-token"

  replication {
    auto {}
  }

  depends_on = [google_project_service.aegis_security_services]
}

resource "google_secret_manager_secret" "slack_webhook" {
  project   = var.project_id
  secret_id = "${var.project_name}-slack-webhook"

  replication {
    auto {}
  }

  depends_on = [google_project_service.aegis_security_services]
}

# Scoped Secret Accessor IAM (Principle of Least Privilege)
resource "google_secret_manager_secret_iam_member" "app_sa_pagerduty_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.pagerduty_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "app_sa_slack_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "vertex_sa_pagerduty_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.pagerduty_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_project_service_identity.vertex_sa.member
}

resource "google_secret_manager_secret_iam_member" "vertex_sa_slack_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_project_service_identity.vertex_sa.member
}

# Least-privilege DLP, Model Armor, and Vertex AI Search viewer bindings
resource "google_project_iam_member" "aegis_app_sa_security_roles" {
  for_each   = toset(local.aegis_extra_sa_roles)
  project    = var.project_id
  role       = each.value
  member     = "serviceAccount:${google_service_account.app_sa.email}"
  depends_on = [google_project_service.aegis_security_services]
}

resource "google_project_iam_member" "aegis_vertex_sa_security_roles" {
  for_each   = toset(local.aegis_extra_sa_roles)
  project    = var.project_id
  role       = each.value
  member     = google_project_service_identity.vertex_sa.member
  depends_on = [google_project_service.aegis_security_services]
}

# Optional Vertex AI Search Runbook Datastore (opt-in via var.enable_vertex_search)
resource "google_discovery_engine_data_store" "sre_runbooks" {
  count                       = var.enable_vertex_search ? 1 : 0
  project                     = var.project_id
  location                    = "global"
  data_store_id               = "${replace(var.project_name, "-", "_")}_runbooks"
  display_name                = "AegisOps Verified SRE Runbooks"
  industry_vertical           = "GENERIC"
  content_config              = "CONTENT_REQUIRED"
  solution_types              = ["SOLUTION_TYPE_SEARCH"]
  create_advanced_site_search = false

  depends_on = [google_project_service.aegis_security_services]
}

output "pagerduty_secret_id" {
  description = "Secret Manager ID for PagerDuty integration token."
  value       = google_secret_manager_secret.pagerduty_token.secret_id
}

output "slack_webhook_secret_id" {
  description = "Secret Manager ID for Slack war-room webhook."
  value       = google_secret_manager_secret.slack_webhook.secret_id
}
