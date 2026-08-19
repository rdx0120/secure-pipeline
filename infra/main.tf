# Artifact bucket + GitHub OIDC role for secure-pipeline.
#
# Two things this module exists to demonstrate, beyond storing artifacts:
#   1. The bucket holds SARIF and normalized findings. Those are sensitive
#      output -- gitleaks findings reference secret locations even after
#      redaction -- so public access is a correctness bug, not a style issue.
#   2. The OIDC trust policy is the part people get wrong. An over-broad `sub`
#      condition lets ANY repository in the org assume this role.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "github_org" {
  type    = string
  default = "rdx0120"
}

variable "github_repo" {
  type    = string
  default = "secure-pipeline"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------- bucket ----

resource "aws_s3_bucket" "artifacts" {
  bucket = "secure-pipeline-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ------------------------------------------------------------------ OIDC ----

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The line that matters. `repo:${org}/*` would let ANY repository in the
    # org assume this role -- including a fork or a newly-created one. Pinned
    # to a single repo and a single ref.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = "secure-pipeline-ci"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

data "aws_iam_policy_document" "artifacts_write" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }
}

resource "aws_iam_role_policy" "artifacts_write" {
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.artifacts_write.json
}
