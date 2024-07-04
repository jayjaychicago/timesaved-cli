import { NextRequest, NextResponse } from 'next/server';
import yaml from 'js-yaml';
import AWS from 'aws-sdk';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';

export async function POST(req: NextRequest) {
  try {
    const { awsCredentials, applicationName, openApiSpec } = await req.json();
    
    if (!awsCredentials || !applicationName || !openApiSpec) {
      throw new Error('Missing AWS credentials, application name, OpenAPI specification');
    }

    // Configure AWS SDK
    AWS.config.update({
      accessKeyId: awsCredentials.accessKeyId,
      secretAccessKey: awsCredentials.secretAccessKey,
      region: awsCredentials.region
    });

    // Delete existing resources
    await deleteExistingResources(applicationName);

    const spec = yaml.load(openApiSpec);
    const terraformConfig = generateTerraformConfig(spec, awsCredentials, applicationName);

    // Create a temporary directory for Terraform files
    const tempDir = `/tmp/terraform-${applicationName}`;
    fs.mkdirSync(tempDir, { recursive: true });

    // Write Lambda function to a file
    const lambdaCode = fs.readFileSync(path.join(process.cwd(), 'src', 'lambda_function.mjs'), 'utf8');
    fs.writeFileSync(path.join(tempDir, 'lambda_function.mjs'), lambdaCode);

    // Create a zip file containing the Lambda function
    const zip = new AdmZip();
    zip.addLocalFile(path.join(tempDir, 'lambda_function.mjs'));
    zip.writeZip(path.join(tempDir, 'lambda_function.zip'));

    // Write Terraform configuration to a file
    fs.writeFileSync(path.join(tempDir, 'main.tf'), terraformConfig);

    // Run Terraform commands
    try {
      execSync('terraform init', { cwd: tempDir, stdio: 'pipe' });
      const applyOutput = execSync('terraform apply -auto-approve', { cwd: tempDir, stdio: 'pipe' });
      
      // Clean up
      fs.rmSync(tempDir, { recursive: true, force: true });

      return NextResponse.json({ output: applyOutput.toString() });
    } catch (error) {
      console.error('Terraform execution error:', error);
      
      // Clean up
      fs.rmSync(tempDir, { recursive: true, force: true });

      return NextResponse.json({ error: `Terraform execution failed: ${error.message}` }, { status: 500 });
    }
  } catch (error) {
    console.error('API route error:', error);
    return NextResponse.json({ error: error.message || 'An unexpected error occurred' }, { status: 400 });
  }
}

async function deleteExistingResources(applicationName: string) {
    const lambda = new AWS.Lambda();
    const apiGateway = new AWS.APIGateway();
    const iam = new AWS.IAM();
  
    const lambdaFunctionName = `${applicationName}-lambda`;
    const roleName = `${lambdaFunctionName}-role`;
  
    // Delete Lambda function
    try {
      await lambda.deleteFunction({ FunctionName: lambdaFunctionName }).promise();
      console.log(`Deleted Lambda function: ${lambdaFunctionName}`);
    } catch (error) {
      console.log(`Lambda function ${lambdaFunctionName} not found or already deleted`);
    }
  
    // Delete API Gateway
    try {
      const apis = await apiGateway.getRestApis().promise();
      const api = apis.items.find(item => item.name === applicationName);
      if (api) {
        await apiGateway.deleteRestApi({ restApiId: api.id }).promise();
        console.log(`Deleted API Gateway: ${applicationName}`);
      }
    } catch (error) {
      console.log(`API Gateway ${applicationName} not found or already deleted`);
    }
  
    // Delete IAM role
    try {
      // First, detach all policies from the role
      const attachedPolicies = await iam.listAttachedRolePolicies({ RoleName: roleName }).promise();
      for (const policy of attachedPolicies.AttachedPolicies) {
        await iam.detachRolePolicy({
          RoleName: roleName,
          PolicyArn: policy.PolicyArn
        }).promise();
        console.log(`Detached policy ${policy.PolicyArn} from role ${roleName}`);
      }
  
      // Then, delete any inline policies
      const inlinePolicies = await iam.listRolePolicies({ RoleName: roleName }).promise();
      for (const policyName of inlinePolicies.PolicyNames) {
        await iam.deleteRolePolicy({
          RoleName: roleName,
          PolicyName: policyName
        }).promise();
        console.log(`Deleted inline policy ${policyName} from role ${roleName}`);
      }
  
      // Finally, delete the role
      await iam.deleteRole({ RoleName: roleName }).promise();
      console.log(`Deleted IAM role: ${roleName}`);
    } catch (error) {
      console.log(`Error deleting IAM role ${roleName}: ${error.message}`);
    }
  }

function generateTerraformConfig(spec: any, awsCredentials: any, applicationName: string) {
    const apiName = applicationName.replace(/\s+/g, '-').toLowerCase();
    const lambdaFunctionName = `${apiName}-lambda`;
  
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
    handler       = "lambda_function.handler"
    runtime       = "nodejs20.x"
  
    source_code_hash = filebase64sha256("lambda_function.zip")
  
    environment {
      variables = {
        REDIS_URL = "redis://127.0.0.1:60379"
      }
    }
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
  `;

  // Generate resources for each path and method in the OpenAPI spec
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    const resourceName = path.replace(/[^a-zA-Z0-9]/g, '_');
    config += `
resource "aws_api_gateway_resource" "${resourceName}" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "${path.replace(/^\//, '')}"
}
`;

    for (const [method, operation] of Object.entries(pathItem)) {
      if (method.toLowerCase() !== 'options') {  // Skip 'options' method as it's usually added automatically
        config += `
resource "aws_api_gateway_method" "${resourceName}_${method}" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.${resourceName}.id
  http_method   = "${method.toUpperCase()}"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "${resourceName}_${method}" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.${resourceName}.id
  http_method = aws_api_gateway_method.${resourceName}_${method}.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda.invoke_arn
}
`;
      }
    }
  }

  // Add deployment resource
  config += `
resource "aws_api_gateway_deployment" "api_deployment" {
  depends_on = [${Object.entries(spec.paths).flatMap(([path, pathItem]) => 
    Object.keys(pathItem)
      .filter(method => method.toLowerCase() !== 'options')
      .map(method => `aws_api_gateway_integration.${path.replace(/[^a-zA-Z0-9]/g, '_')}_${method}`)
  ).join(', ')}]

  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = "prod"
}

output "api_url" {
  value = aws_api_gateway_deployment.api_deployment.invoke_url
}
`;

  return config;
}


