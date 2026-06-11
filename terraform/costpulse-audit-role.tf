# ─────────────────────────────────────────────────────────────────────────────
# CostPulse AWS Cost Audit — Read-Only Access Role
# costpulse.io · aws@costpulse.io
#
# WHAT THIS CREATES
#   One IAM role ("CostPulseAuditRole") that lets the CostPulse auditor account
#   READ your billing data and resource metadata. Nothing else.
#
# WHAT IT CANNOT DO
#   - No write/modify/delete permissions of any kind (explicit deny included)
#   - No access to data inside S3 objects, databases, secrets, or parameters
#   - Only assumable by the CostPulse account, and only with the external ID
#     we share with you privately
#
# WHEN THE AUDIT IS DONE
#   terraform destroy   (or delete the role in the IAM console)
#
# USAGE
#   terraform init
#   terraform apply -var="external_id=<the ID we sent you>"
#   ...then send us the role_arn output.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ── Variables ────────────────────────────────────────────────────────────────

variable "costpulse_account_id" {
  description = "CostPulse auditor AWS account ID (we provide this — do not change)."
  type        = string
  default     = "922981237283"

  validation {
    condition     = can(regex("^\\d{12}$", var.costpulse_account_id))
    error_message = "Must be a 12-digit AWS account ID."
  }
}

variable "external_id" {
  description = "External ID shared privately by CostPulse. Required to assume the role."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.external_id) >= 16
    error_message = "External ID must be at least 16 characters."
  }
}

variable "role_name" {
  description = "Name of the audit role created in your account."
  type        = string
  default     = "CostPulseAuditRole"
}

# ── Trust policy: only CostPulse, only with the external ID ──────────────────

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "AllowCostPulseAuditorWithExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.costpulse_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "audit" {
  name                 = var.role_name
  description          = "Read-only access for the CostPulse cost audit. Safe to delete after the engagement."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600 # 1-hour sessions

  tags = {
    Purpose   = "costpulse-cost-audit"
    ManagedBy = "terraform"
    Contact   = "aws@costpulse.io"
  }
}

# ── AWS-managed read-only policies ───────────────────────────────────────────
# ViewOnlyAccess  = resource metadata across services (list/describe, no data reads)
# BillingReadOnly = Billing console, invoices, payment history (read only)

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "billing_read" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"
}

# ── Custom read-only policy for cost analysis APIs ───────────────────────────

data "aws_iam_policy_document" "cost_analysis" {
  statement {
    sid    = "CostAndUsageReadOnly"
    effect = "Allow"
    actions = [
      # Cost Explorer
      "ce:Describe*",
      "ce:Get*",
      "ce:List*",
      # Cost & Usage Reports + pricing
      "cur:DescribeReportDefinitions",
      "pricing:DescribeServices",
      "pricing:GetAttributeValues",
      "pricing:GetProducts",
      # Commitments
      "savingsplans:Describe*",
      "savingsplans:List*",
      # Budgets
      "budgets:Describe*",
      "budgets:View*",
      # Rightsizing signals
      "compute-optimizer:Describe*",
      "compute-optimizer:Get*",
      # Trusted Advisor cost checks (requires Business/Enterprise support)
      "support:DescribeTrustedAdvisorCheckResult",
      "support:DescribeTrustedAdvisorChecks",
      "trustedadvisor:Describe*",
      # Usage metrics for rightsizing analysis
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListMetrics",
    ]
    resources = ["*"]
  }

  # Belt-and-suspenders: explicitly deny anything that isn't a read.
  statement {
    sid    = "ExplicitDenyAllWrites"
    effect = "Deny"
    actions = [
      "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Update*", "iam:Attach*", "iam:Detach*",
      "ec2:Create*", "ec2:Delete*", "ec2:Modify*", "ec2:Terminate*", "ec2:Run*", "ec2:Start*", "ec2:Stop*",
      "rds:Create*", "rds:Delete*", "rds:Modify*",
      "s3:Put*", "s3:Delete*", "s3:GetObject*", # also deny object reads — metadata only
      "secretsmanager:*",
      "ssm:GetParameter*",
      "kms:Decrypt",
      "lambda:Invoke*",
      "sts:AssumeRole",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cost_analysis" {
  name        = "${var.role_name}-cost-analysis"
  description = "Read-only cost analysis APIs for the CostPulse audit, with explicit write denies."
  policy      = data.aws_iam_policy_document.cost_analysis.json
}

resource "aws_iam_role_policy_attachment" "cost_analysis" {
  role       = aws_iam_role.audit.name
  policy_arn = aws_iam_policy.cost_analysis.arn
}

# ── Outputs ──────────────────────────────────────────────────────────────────

output "role_arn" {
  description = "Send this ARN to aws@costpulse.io to begin the audit."
  value       = aws_iam_role.audit.arn
}

output "cleanup_reminder" {
  value = "After the audit: run `terraform destroy` to remove all audit access."
}
