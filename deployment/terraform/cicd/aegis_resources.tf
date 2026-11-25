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

# Multi-environment (staging + prod) Secret Manager, Cloud DLP, and Model Armor IaC

variable "min_instances" {
  type        = number
  description = "Minimum warm Agent Runtime instances across staging and prod."
  default     = 0
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
  for_each = {
    for pair in setproduct(keys(local.deploy_project_ids), local.aegis_security_apis) :
    "${pair[0]}_${replace(pair[1], ".", "_")}" => {
      project = local.deploy_project_ids[pair[0]]
      service = pair[1]
    }
  }
  project            = each.value.project
  service            = each.value.service
  disable_on_destroy = false
}

resource "google_secret_manager_secret" "pagerduty_token" {
  for_each  = local.deploy_project_ids
  project   = each.value
  secret_id = "${var.project_name}-pagerduty-token"

  replication {
    auto {}
  }

  depends_on = [google_project_service.aegis_security_services]
}

resource "google_secret_manager_secret" "slack_webhook" {
  for_each  = local.deploy_project_ids
  project   = each.value
  secret_id = "${var.project_name}-slack-webhook"

  replication {
    auto {}
  }

  depends_on = [google_project_service.aegis_security_services]
}

resource "google_secret_manager_secret_iam_member" "app_sa_pagerduty_accessor" {
  for_each  = local.deploy_project_ids
  project   = each.value
  secret_id = google_secret_manager_secret.pagerduty_token[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa[each.key].email}"
}

resource "google_secret_manager_secret_iam_member" "app_sa_slack_accessor" {
  for_each  = local.deploy_project_ids
  project   = each.value
  secret_id = google_secret_manager_secret.slack_webhook[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa[each.key].email}"
}

resource "google_project_iam_member" "aegis_app_sa_security_roles" {
  for_each = {
    for pair in setproduct(keys(local.deploy_project_ids), local.aegis_extra_sa_roles) :
    "${pair[0]}_${pair[1]}" => {
      env     = pair[0]
      project = local.deploy_project_ids[pair[0]]
      role    = pair[1]
    }
  }
  project    = each.value.project
  role       = each.value.role
  member     = "serviceAccount:${google_service_account.app_sa[each.value.env].email}"
  depends_on = [google_project_service.aegis_security_services]
}
