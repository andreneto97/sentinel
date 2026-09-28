resource "aws_lambda_function" "worker" {
  function_name = "acme-worker"
  runtime       = "nodejs20.x"
  handler       = "index.handler"
}
