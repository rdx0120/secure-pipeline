output "ci_role_arn" {
  value = aws_iam_role.ci.arn
}

output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.id
}
