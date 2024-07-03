import { NextRequest, NextResponse } from 'next/server'
import yaml from 'js-yaml'
import { v4 as uuidv4 } from 'uuid'

export async function POST(req: NextRequest) {
  try {
    const { awsCredentials, openApiSpec } = await req.json()
    const spec = yaml.load(openApiSpec)
    const terraformConfig = generateTerraformConfig(spec, awsCredentials)
    return NextResponse.json({ output: terraformConfig })
  } catch (error) {
    return NextResponse.json({ error: 'Invalid OpenAPI specification or AWS credentials' }, { status: 400 })
  }
}

function generateTerraformConfig(spec: any, awsCredentials: any) {
  const apiName = spec.info.title.replace(/\s+/g, '-').toLowerCase()
  const lambdaFunctionName = `${apiName}-lambda`

  let config = `
provider "aws" {
  region     = "${awsCredentials.region}"
  access_key = "${awsCredentials.accessKeyId}"
  secret_key = "${awsCredentials.secretAccessKey}"
}

resource "aws_api_gateway_rest_api" "api" {
  name = "${apiName}"
}

resource "aws_lambda_function" "api_lambda" {
  filename      = "lambda_function.zip"
  function_name = "${lambdaFunctionName}"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"

  source_code_hash = filebase64sha256("lambda_function.zip")
}

resource "aws_iam_role" "lambda_role" {
  name = "${lambdaFunctionName}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role.name
}

resource "aws_api_gateway_authorizer" "api_authorizer" {
  name                   = "${apiName}-authorizer"
  rest_api_id            = aws_api_gateway_rest_api.api.id
  type                   = "COGNITO_USER_POOLS"
  provider_arns          = [aws_cognito_user_pool.pool.arn]
}

resource "aws_cognito_user_pool" "pool" {
  name = "${apiName}-user-pool"
}

resource "aws_cognito_user_pool_client" "client" {
  name         = "${apiName}-user-pool-client"
  user_pool_id = aws_cognito_user_pool.pool.id
}
`

  // Generate resources for each path and method in the OpenAPI spec
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      const resourceId = uuidv4().split('-')[0]
      config += `
resource "aws_api_gateway_resource" "${resourceId}" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "${path.replace(/^\//, '')}"
}

resource "aws_api_gateway_method" "${resourceId}_${method}" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.${resourceId}.id
  http_method   = "${method.toUpperCase()}"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.api_authorizer.id
}

resource "aws_api_gateway_integration" "${resourceId}_${method}" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.${resourceId}.id
  http_method = aws_api_gateway_method.${resourceId}_${method}.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda.invoke_arn
}
`
    }
  }

  // Add deployment resource
  config += `
resource "aws_api_gateway_deployment" "api_deployment" {
  depends_on = [${Object.entries(spec.paths).flatMap(([path, pathItem]) => 
    Object.keys(pathItem).map(method => `aws_api_gateway_integration.${uuidv4().split('-')[0]}_${method}`)
  ).join(', ')}]

  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "prod"
}

output "api_url" {
  value = aws_api_gateway_deployment.api_deployment.invoke_url
}
`

  return config
}