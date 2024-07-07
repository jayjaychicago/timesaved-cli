import { NextRequest, NextResponse } from 'next/server';
import yaml from 'js-yaml';
import AWS from 'aws-sdk';
import { execSync, exec, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';
import { v4 as uuidv4 } from 'uuid';
import { tmpdir } from 'os';

function execWithTimeout(command: string, cwd: string, timeout: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = exec(command, { cwd, encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });

    setTimeout(() => {
      child.kill();
      reject(new Error(`Command timed out after ${timeout}ms: ${command}`));
    }, timeout);
  });
}

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

interface RequestBody {
  awsCredentials: AwsCredentials;
  applicationName: string;
  openApiSpec: string;
}

export async function POST(req: NextRequest) {
  try {
    const body: RequestBody = await req.json();
    const { awsCredentials, applicationName, openApiSpec } = body;
    
    if (!awsCredentials || !applicationName || !openApiSpec) {
      throw new Error('Missing AWS credentials, application name, or OpenAPI specification');
    }

    console.log('API route called with application name:', applicationName);

    // Read auth.js.tpl and index.html contents
    const authJsTemplate = fs.readFileSync(path.join(process.cwd(), 'public/auth_website', 'auth.js.tpl'), 'utf8');
    const indexHtmlTemplate = fs.readFileSync(path.join(process.cwd(), 'public/auth_website', 'index.html'), 'utf8');
    var lambdaFunctionTemplate = fs.readFileSync(path.join(process.cwd(), 'public', 'lambda_function.mjs'), 'utf8');

    const spec = yaml.load(openApiSpec) as any;
    // Configure AWS SDK
    AWS.config.update(awsCredentials);

    // do the next two lines in one line
    const [terraformConfig, updatedLambdaFunctionTemplate] = generateTerraformConfig(spec, awsCredentials, applicationName, authJsTemplate, indexHtmlTemplate, openApiSpec, lambdaFunctionTemplate);
    lambdaFunctionTemplate = updatedLambdaFunctionTemplate;

    console.log('Terraform configuration completed.');

    const zip0 = new AdmZip();
    zip0.addFile('lambda_function.mjs', Buffer.from(lambdaFunctionTemplate));
    // Get zip buffer and convert to Base64
    const zipBuffer0 = zip0.toBuffer();

    // Create in-memory zip file
    const zip = new AdmZip();

    // Add files to the zip
    zip.addFile('auth.js.tpl', Buffer.from(authJsTemplate));
    zip.addFile('index.html', Buffer.from(indexHtmlTemplate));
    zip.addFile('lambda_function.zip', Buffer.from(zipBuffer0));
    zip.addFile(`${applicationName}.tf`, Buffer.from(terraformConfig));

    // Generate and add cleanup script
    const cleanupScript = generateAwsCleanupScript(applicationName);
    zip.addFile('delete.sh', Buffer.from(cleanupScript));

    // Generate and add Terraform script
    const terraformScript = generateTerraformScript();
    zip.addFile('terraform.sh', Buffer.from(terraformScript));

    const readmeContent = readme();
    zip.addFile('README.md', Buffer.from(readmeContent));

    // Get zip buffer and convert to Base64
    const zipBuffer = zip.toBuffer();
    const base64Zip = zipBuffer.toString('base64');

    console.log('Terraform execution completed successfully.');
    
    // Return JSON response with Base64 encoded ZIP
    return NextResponse.json({
      message: 'Terraform execution completed successfully.',
      outputs: {
        zipFileContent: base64Zip,
        filename: `terraform-${applicationName}.zip`
      }
    });
  
  } catch (error) {
    console.error('API route error:', error);
    if (error instanceof Error) {
      return NextResponse.json({ error: error.message || 'An unexpected error occurred' }, { status: 400 });
    }
    return NextResponse.json({ error: 'An unexpected error occurred' }, { status: 400 });
  }
}


async function deleteExistingResources(applicationName: string): Promise<void> {
  const lambda = new AWS.Lambda();
  const apiGateway = new AWS.APIGateway();
  const iam = new AWS.IAM();
  const cognito = new AWS.CognitoIdentityServiceProvider();
  const cloudfront = new AWS.CloudFront();
  const s3 = new AWS.S3();

  const lambdaFunctionName = `${applicationName}-lambda`;
  const roleName = `${lambdaFunctionName}-role`;
  const userPoolName = `${applicationName}-user-pool`;
  const bucketName = `${applicationName.replace(/\s+/g, '-').toLowerCase()}-auth-website`;

  console.log('Starting resource deletion process...');

  // Helper function to handle timeouts
  const withTimeout = <T>(promise: Promise<T>, ms: number, errorMessage: string): Promise<T> => {
    let timeoutId: NodeJS.Timeout;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(`Timed out in ${ms}ms: ${errorMessage}`));
      }, ms);
    });

    return Promise.race([
      promise,
      timeoutPromise
    ]).finally(() => clearTimeout(timeoutId));
  };

  try {
    console.log('Deleting CloudFront distribution...');
    await withTimeout(
      (async () => {
        const distributions = await cloudfront.listDistributions().promise();
        const distribution = distributions.DistributionList?.Items?.find(
          item => item.Comment === applicationName
        );
        if (distribution && distribution.Id) {
          const distributionDetails = await cloudfront.getDistribution({ Id: distribution.Id }).promise();
          if (distributionDetails.ETag) {
            await cloudfront.deleteDistribution({
              Id: distribution.Id,
              IfMatch: distributionDetails.ETag
            }).promise();
            console.log(`Deleted CloudFront distribution: ${distribution.Id}`);
          }
        } else {
          console.log(`CloudFront distribution not found for application: ${applicationName}`);
        }
      })(),
      300000,  // Timeout of 5 minutes
      'CloudFront distribution deletion timeout'
    );
  } catch (error) {
    console.error('Error deleting CloudFront distribution:', error);
  }

  console.log('Deleting Lambda function...');
  await withTimeout(
    (async () => {
      try {
        await lambda.deleteFunction({ FunctionName: lambdaFunctionName }).promise();
        console.log(`Deleted Lambda function: ${lambdaFunctionName}`);
      } catch (error) {
        console.log(`Lambda function ${lambdaFunctionName} not found or already deleted`);
      }
    })(),
    60000,
    'Lambda function deletion'
  );

  console.log('Deleting API Gateway...');
  await withTimeout(
    (async () => {
      const apis = await apiGateway.getRestApis().promise();
      const api = apis.items?.find(item => item.name === applicationName);
      if (api && api.id) {
        await apiGateway.deleteRestApi({ restApiId: api.id }).promise();
        console.log(`Deleted API Gateway: ${applicationName}`);
      }
    })(),
    60000,
    'API Gateway deletion'
  );

  console.log('Deleting IAM role...');
  await withTimeout(
    (async () => {
      try {
        const attachedPolicies = await iam.listAttachedRolePolicies({ RoleName: roleName }).promise();
        for (const policy of attachedPolicies.AttachedPolicies || []) {
          if (policy.PolicyArn) {
            await iam.detachRolePolicy({
              RoleName: roleName,
              PolicyArn: policy.PolicyArn
            }).promise();
            console.log(`Detached policy ${policy.PolicyArn} from role ${roleName}`);
          }
        }

        const inlinePolicies = await iam.listRolePolicies({ RoleName: roleName }).promise();
        for (const policyName of inlinePolicies.PolicyNames || []) {
          await iam.deleteRolePolicy({
            RoleName: roleName,
            PolicyName: policyName
          }).promise();
          console.log(`Deleted inline policy ${policyName} from role ${roleName}`);
        }

        await iam.deleteRole({ RoleName: roleName }).promise();
        console.log(`Deleted IAM role: ${roleName}`);
      } catch (error) {
        console.log(`Error deleting IAM role ${roleName}: ${(error as Error).message}`);
      }
    })(),
    60000,
    'IAM role deletion'
  );

  console.log('Deleting Cognito User Pool...');
  await withTimeout(
    (async () => {
      const listPoolsResponse = await cognito.listUserPools({ MaxResults: 60 }).promise();
      const userPool = listPoolsResponse.UserPools?.find(pool => pool.Name === userPoolName);
      if (userPool && userPool.Id) {
        await cognito.deleteUserPool({ UserPoolId: userPool.Id }).promise();
        console.log(`Deleted Cognito User Pool: ${userPoolName}`);
      }
    })(),
    60000,
    'Cognito User Pool deletion'
  );

  console.log('Deleting S3 bucket...');
  await withTimeout(
    (async () => {
      try {
        const objects = await s3.listObjectsV2({ Bucket: bucketName }).promise();
        if (objects.Contents && objects.Contents.length > 0) {
          await s3.deleteObjects({
            Bucket: bucketName,
            Delete: { Objects: objects.Contents.map(({ Key }) => ({ Key: Key || '' })) }
          }).promise();
        }

        await s3.deleteBucket({ Bucket: bucketName }).promise();
        console.log(`Deleted S3 bucket: ${bucketName}`);
      } catch (error) {
        if ((error as AWS.AWSError).code !== 'NoSuchBucket') {
          console.log(`Error deleting S3 bucket: ${(error as Error).message}`);
        }
      }
    })(),
    60000,
    'S3 bucket deletion'
  );

  console.log('Resource deletion process completed successfully.');
}

function readme(): string {
  return `
  In order to create your API and API dev Portal, the scripts in this folder will:
  * Create an AWS API Gateway to handle your API traffic
  * Create an AWS Cognito User Pool for user authentication using login and password to produce an API bearer token
  * Create an AWS Lambda function to handle API requests
  * Create an S3 bucket to host your API documentation and authentication website
  * Create a CloudFront distribution to serve your website over HTTPS
  
  In order to proceed, all you need to do is run in this folder:
  chmod +x terraform.sh delete.sh
  ./terraform.sh <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS> <AWS_REGION> in order to create all the resources described above
  ./delete.shin order to delete all the resources created by the terraform script
  
  The terraform script will:
  * Create all the AWS resources you need
  * Output the URL of your API Gateway so that you can begin using your API
  * Output the URL of your authentication website so that you can obtain an API bearer token to use your API
  * Output the name of the lambda function that you will need to modify in order to implement your API

  `}


function generateTerraformScript(): string {
  return `
#!/bin/bash

# Prompt for AWS credentials and region if not provided as arguments
ACCESS_KEY_ID="\${1}"
SECRET_ACCESS_KEY="\${2}"
REGION="\${3}"

if [ -z "\${ACCESS_KEY_ID}" ]; then
  read -p "Enter your AWS Access Key ID: " ACCESS_KEY_ID
fi
if [ -z "\${SECRET_ACCESS_KEY}" ]; then
  read -p "Enter your AWS Secret Access Key: " SECRET_ACCESS_KEY
fi
if [ -z "\${REGION}" ]; then
  read -p "Enter your AWS Region: " REGION
fi

# Find the .tf file in the current directory
TF_FILE=$(find . -maxdepth 1 -name "*.tf" | head -n 1)

if [ -z "$TF_FILE" ]; then
  echo "No .tf file found in the current directory."
  exit 1
fi

# Function to escape only the '/' character
escape_slash() {
  echo "$1" | sed 's/\//\\\//g'
}

awk -v access_key="$ACCESS_KEY_ID" \
    -v secret_key="$SECRET_ACCESS_KEY" \
    -v region="$REGION" \
    '{gsub(/ACCESS_KEY_ID_PLACEHOLDER/, access_key); gsub(/SECRET_ACCESS_KEY_PLACEHOLDER/, secret_key); gsub(/REGION_PLACEHOLDER/, region)}1' "$TF_FILE" > "$TF_FILE.tmp" && mv "$TF_FILE.tmp" "$TF_FILE"

# Initialize, plan and apply Terraform
terraform init
terraform plan -out=tfplan
terraform show tfplan
terraform apply -auto-approve
`;
}

function generateAwsCleanupScript(applicationName: string): string {
  return `#!/bin/bash

# Function to delete existing AWS resources
delete_existing_resources() {
    local application_name="$1"
    local lambda_function_name="\${application_name}-lambda"
    local role_name="\${lambda_function_name}-role"
    local user_pool_name="\${application_name}-user-pool"
    local bucket_name=$(echo "\${application_name}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9-]/-/g')-auth-website

    echo "Starting resource deletion process..."

    # Delete CloudFront distribution
    echo "Deleting CloudFront distribution..."
    distribution_id=$(aws cloudfront list-distributions --query "DistributionList.Items[?Comment=='\${application_name}'].Id" --output text)
    if [ -n "$distribution_id" ]; then
        etag=$(aws cloudfront get-distribution --id "$distribution_id" --query 'ETag' --output text)
        aws cloudfront delete-distribution --id "$distribution_id" --if-match "$etag"
        echo "Deleted CloudFront distribution: $distribution_id"
    else
        echo "CloudFront distribution not found for application: \${application_name}"
    fi

    # Delete Lambda function
    echo "Deleting Lambda function..."
    aws lambda delete-function --function-name "$lambda_function_name" || echo "Lambda function \${lambda_function_name} not found or already deleted"

    # Delete API Gateway
    echo "Deleting API Gateway..."
    api_id=$(aws apigateway get-rest-apis --query "items[?name=='\${application_name}'].id" --output text)
    if [ -n "$api_id" ]; then
        aws apigateway delete-rest-api --rest-api-id "$api_id"
        echo "Deleted API Gateway: \${application_name}"
    fi

    # Delete IAM role
    echo "Deleting IAM role..."
    attached_policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyArn' --output text)
    for policy in $attached_policies; do
        aws iam detach-role-policy --role-name "$role_name" --policy-arn "$policy"
        echo "Detached policy $policy from role $role_name"
    done

    inline_policies=$(aws iam list-role-policies --role-name "$role_name" --query 'PolicyNames' --output text)
    for policy in $inline_policies; do
        aws iam delete-role-policy --role-name "$role_name" --policy-name "$policy"
        echo "Deleted inline policy $policy from role $role_name"
    done

    aws iam delete-role --role-name "$role_name" || echo "Error deleting IAM role \${role_name}"

    # Delete Cognito User Pool
    echo "Deleting Cognito User Pool..."
    user_pool_id=$(aws cognito-idp list-user-pools --max-results 60 --query "UserPools[?Name=='\${user_pool_name}'].Id" --output text)
    if [ -n "$user_pool_id" ]; then
        aws cognito-idp delete-user-pool --user-pool-id "$user_pool_id"
        echo "Deleted Cognito User Pool: \${user_pool_name}"
    fi

    # Delete S3 bucket
    echo "Deleting S3 bucket..."
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        aws s3 rm "s3://\${bucket_name}" --recursive
        aws s3 rb "s3://\${bucket_name}" --force
        echo "Deleted S3 bucket: \${bucket_name}"
    else
        echo "S3 bucket \${bucket_name} not found or already deleted"
    fi

    echo "Resource deletion process completed successfully."
}

# Call the function with the provided application name
delete_existing_resources "${applicationName}"
`;
}

  function prepareOpenApiSpec(openApiSpec:string) {
    // Regex to find existing server URL entries or spot where to insert a new one
    const serverUrlRegex = /servers:\s*\n\s*- url: ["']([^"']+)["']/;
    const hasServerUrl = serverUrlRegex.test(openApiSpec);
  
    if (hasServerUrl) {
      // Replace existing URL with a placeholder
      return openApiSpec.replace(serverUrlRegex, "servers:\n  - url: '{{{api_url}}}'\n");
    } else {
      // Insert a new server entry if none exists
      const insertPosition = openApiSpec.indexOf('paths:');
      return openApiSpec.slice(0, insertPosition) + "servers:\n  - url: '{{{api_url}}}'\n" + openApiSpec.slice(insertPosition);
    }
  }
  
  

    function generateTerraformConfig(spec: any, awsCredentials: any, applicationName: string, authJsTemplate: string, indexHtmlTemplate: string, openApiSpec:string, lambdaFunctionTemplate:string) {
      const apiName = applicationName.replace(/\s+/g, '-').toLowerCase();
      const lambdaFunctionName = `${apiName}-lambda`;
      const bucketName = `${apiName}-auth-website`;
      console.log('Resource generation begins.');
      console.log('First line of openapi spec:', openApiSpec.split('\n')[0]);

      const preparedSpec = prepareOpenApiSpec(openApiSpec);

      var lambda_placeholder_replacement = '';

    

      let config = `
      provider "aws" {
        region     = "${awsCredentials.region}"
        access_key = "${awsCredentials.accessKeyId}"
        secret_key = "${awsCredentials.secretAccessKey}"
      }
      
      resource "aws_cognito_user_pool" "main" {
        name = "${applicationName}-user-pool"
    
        password_policy {
          minimum_length    = 8
          require_lowercase = true
          require_numbers   = true
          require_symbols   = true
          require_uppercase = true
        }
    
        auto_verified_attributes = ["email"]
    
        schema {
          name                = "email"
          attribute_data_type = "String"
          required            = true
          mutable             = true
        }
      }
    
      resource "aws_cognito_user_pool_client" "main" {
        name         = "${applicationName}-user-pool-client"
        user_pool_id = aws_cognito_user_pool.main.id
      
        generate_secret                      = false
        explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"]
        allowed_oauth_flows_user_pool_client = true
        allowed_oauth_flows                  = ["implicit"]
        allowed_oauth_scopes                 = ["email", "openid"]
        callback_urls                        = ["http://localhost:3000"]
        supported_identity_providers         = ["COGNITO"]
      }
    
      locals {

        index_html_template = <<EOF
${indexHtmlTemplate}
EOF
      
auth_js_template = <<EOF
${authJsTemplate}
EOF

      openapi_yaml_content2 = <<-EOF
${preparedSpec}
EOF
      
        index_html_content = replace(local.index_html_template, "{{{user_pool_id}}}", aws_cognito_user_pool.main.id)
        auth_js_content = replace(
          replace(local.auth_js_template, "{{{user_pool_id}}}", aws_cognito_user_pool.main.id),
          "{{{client_id}}}", aws_cognito_user_pool_client.main.id
        )
        openapi_yaml_content = replace(local.openapi_yaml_content2, "{{{api_url}}}", aws_api_gateway_deployment.api_deployment.invoke_url)
      }
      
      

      resource "aws_s3_bucket" "website" {
        bucket = "${bucketName}"
        force_destroy = true
      }
      
      resource "aws_s3_bucket_ownership_controls" "website" {
        bucket = aws_s3_bucket.website.id
        rule {
          object_ownership = "BucketOwnerPreferred"
        }
      }
      
      resource "aws_s3_bucket_public_access_block" "website" {
        bucket = aws_s3_bucket.website.id
      
        block_public_acls       = false
        block_public_policy     = false
        ignore_public_acls      = false
        restrict_public_buckets = false
      }
      
      resource "aws_s3_bucket_acl" "website" {
        depends_on = [
          aws_s3_bucket_ownership_controls.website,
          aws_s3_bucket_public_access_block.website,
        ]
      
        bucket = aws_s3_bucket.website.id
        acl    = "public-read"
      }
      
      resource "aws_s3_bucket_website_configuration" "website" {
        bucket = aws_s3_bucket.website.id
      
        index_document {
          suffix = "index.html"
        }
      
        error_document {
          key = "error.html"
        }
      }
      



      
    /*
    resource "aws_cloudfront_distribution" "website" {
      origin {
        domain_name = aws_s3_bucket_website_configuration.website.website_endpoint
        origin_id   = "S3-\${aws_s3_bucket.website.bucket}"
    
        custom_origin_config {
          http_port              = 80
          https_port             = 443
          origin_protocol_policy = "http-only"
          origin_ssl_protocols   = ["TLSv1.2"]
        }
      }
    
      enabled             = true
      default_root_object = "index.html"
    
      default_cache_behavior {
        allowed_methods  = ["GET", "HEAD"]
        cached_methods   = ["GET", "HEAD"]
        target_origin_id = "S3-\${aws_s3_bucket.website.bucket}"
    
        forwarded_values {
          query_string = false
          cookies {
            forward = "none"
          }
        }
    
        viewer_protocol_policy = "redirect-to-https"
        min_ttl                = 0
        default_ttl            = 3600
        max_ttl                = 86400
      }
    
      restrictions {
        geo_restriction {
          restriction_type = "none"
        }
      }
    
      viewer_certificate {
        cloudfront_default_certificate = true
      }

      custom_error_response {
        error_caching_min_ttl = 300
        error_code            = 404
        response_code         = 404
        response_page_path    = "/error.html"
      }
    
      tags = {
        Name = "${applicationName}-cloudfront"
      }

    }
    */


    resource "aws_s3_object" "index_html" {
      depends_on   = [aws_s3_bucket_public_access_block.website, aws_api_gateway_deployment.api_deployment]
      bucket       = aws_s3_bucket.website.id
      key          = "index.html"
      content_type = "text/html"
      content      = local.index_html_content
      etag         = md5(local.index_html_content)
      acl          = "public-read"
    }
    
    resource "aws_s3_object" "auth_js" {
      depends_on   = [aws_s3_bucket_public_access_block.website, aws_api_gateway_deployment.api_deployment]
      bucket       = aws_s3_bucket.website.id
      key          = "auth.js"
      content_type = "application/javascript"
      content      = local.auth_js_content
      etag         = md5(local.auth_js_content)
      acl          = "public-read"
    }  

    resource "aws_s3_object" "openapi_yaml" {
      depends_on   = [aws_s3_bucket_public_access_block.website, aws_api_gateway_deployment.api_deployment]
      bucket       = "${bucketName}"
      key          = "openapi.yaml"
      content_type = "application/x-yaml"
      content      = local.openapi_yaml_content
      etag         = md5(local.openapi_yaml_content)
      acl          = "public-read"
    }  

    resource "aws_api_gateway_rest_api" "api" {
      name = "${apiName}"
      description = "API Gateway for ${applicationName}"
    }

    
    
    
    resource "aws_api_gateway_authorizer" "cognito" {
      name          = "cognito-authorizer"
      type          = "COGNITO_USER_POOLS"
      rest_api_id   = aws_api_gateway_rest_api.api.id
      provider_arns = [aws_cognito_user_pool.main.arn]
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

    resource "aws_lambda_permission" "api_gateway_permission" {
      statement_id  = "AllowExecutionFromAPIGateway"
      action        = "lambda:InvokeFunction"
      function_name = aws_lambda_function.api_lambda.function_name
      principal     = "apigateway.amazonaws.com"
    
      // This source_arn now specifies that any part of the API can invoke the Lambda
     
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
    
    
    resource "aws_iam_role_policy" "lambda_cognito_policy" {
      name = "${lambdaFunctionName}-cognito-policy"
      role = aws_iam_role.lambda_role.id
    
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Effect = "Allow"
            Action = [
              "cognito-idp:AdminInitiateAuth",
              "cognito-idp:AdminCreateUser",
              "cognito-idp:AdminSetUserPassword"
            ]
            Resource = aws_cognito_user_pool.main.arn
          }
        ]
      })
    }
    `;
    
      const dependsOnList = [];
    
      // Generate resources for each path and method in the OpenAPI spec
      for (const [path, pathItem] of Object.entries(spec.paths)) {
        const resourceName = path.replace(/[^a-zA-Z0-9]/g, '_').replace(/^_/, '');
        const uniqueId = uuidv4().split('-')[0]; // Use first part of UUID for brevity
    
        config += `
    resource "aws_api_gateway_resource" "${resourceName}_${uniqueId}" {
      rest_api_id = aws_api_gateway_rest_api.api.id
      parent_id   = aws_api_gateway_rest_api.api.root_resource_id
      path_part   = "${path.replace(/^\//, '')}"
    }
    `;
    
        for (const [method, operation] of Object.entries(pathItem as Record<string, unknown>)) {
          if (method.toLowerCase() !== 'options') {
            const integrationResourceName = `${resourceName}_${method.toLowerCase()}_${uniqueId}`;
            dependsOnList.push(`aws_api_gateway_integration.${integrationResourceName}`);
            lambda_placeholder_replacement += `
                 if (event.httpMethod === '${method.toUpperCase()}' && event.resource === '${path}') {
                  // Add your code here
                  return {
                    statusCode: 200,
                    body: JSON.stringify({
                      message: 'Your ${method.toUpperCase()} method on ${path} works!'
                    })
                  };
            `;
    
            config += `
    resource "aws_api_gateway_method" "${integrationResourceName}" {
      rest_api_id   = aws_api_gateway_rest_api.api.id
      resource_id   = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method   = "${method.toUpperCase()}"
      authorization = "COGNITO_USER_POOLS"
      authorizer_id = aws_api_gateway_authorizer.cognito.id
    }
    
    resource "aws_api_gateway_integration" "${integrationResourceName}" {
      rest_api_id = aws_api_gateway_rest_api.api.id
      resource_id = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method = aws_api_gateway_method.${integrationResourceName}.http_method
    
      integration_http_method = "POST"
      type                    = "AWS_PROXY"
      uri                     = aws_lambda_function.api_lambda.invoke_arn
    }
    `;
          }
        }
    
        // Add OPTIONS method for CORS
        config += `
    resource "aws_api_gateway_method" "${resourceName}_options_${uniqueId}" {
      rest_api_id   = aws_api_gateway_rest_api.api.id
      resource_id   = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method   = "OPTIONS"
      authorization = "NONE"
    }
    
    resource "aws_api_gateway_integration" "${resourceName}_options_${uniqueId}" {
      rest_api_id = aws_api_gateway_rest_api.api.id
      resource_id = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method = aws_api_gateway_method.${resourceName}_options_${uniqueId}.http_method
      type        = "MOCK"
    
      request_templates = {
        "application/json" = jsonencode({ "statusCode" : 200 })
      }
    }
    
    resource "aws_api_gateway_method_response" "${resourceName}_options_200_${uniqueId}" {
      rest_api_id = aws_api_gateway_rest_api.api.id
      resource_id = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method = aws_api_gateway_method.${resourceName}_options_${uniqueId}.http_method
      status_code = "200"
    
      response_models = {
        "application/json" = "Empty"
      }
    
      response_parameters = {
        "method.response.header.Access-Control-Allow-Headers" = true
        "method.response.header.Access-Control-Allow-Methods" = true
        "method.response.header.Access-Control-Allow-Origin"  = true
      }
    }
    
    resource "aws_api_gateway_integration_response" "${resourceName}_options_200_${uniqueId}" {
      rest_api_id = aws_api_gateway_rest_api.api.id
      resource_id = aws_api_gateway_resource.${resourceName}_${uniqueId}.id
      http_method = aws_api_gateway_method.${resourceName}_options_${uniqueId}.http_method
      status_code = aws_api_gateway_method_response.${resourceName}_options_200_${uniqueId}.status_code
    
      response_parameters = {
        "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
        "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS,POST,PUT'"
        "method.response.header.Access-Control-Allow-Origin"  = "'*'"
      }
    
      depends_on = [aws_api_gateway_integration.${resourceName}_options_${uniqueId}]
    }
    
    `;
      }
    
      // Add deployment resource
      config += `
    resource "aws_api_gateway_deployment" "api_deployment" {
      depends_on = [${dependsOnList.join(', ')}]
    
      rest_api_id = aws_api_gateway_rest_api.api.id
      stage_name  = "prod"
    }
    
    output "api_url" {
      value = aws_api_gateway_deployment.api_deployment.invoke_url
    }
    
    output "cognito_user_pool_id" {
      value = aws_cognito_user_pool.main.id
    }
    
    output "cognito_app_client_id" {
      value = aws_cognito_user_pool_client.main.id
    }

    output "s3_bucket_website_endpoint" {
      value = "https://\${aws_s3_bucket.website.bucket}.s3-${awsCredentials.region}.amazonaws.com/index.html"
    }

    output "lambda_function_name" {
      value = aws_lambda_function.api_lambda.function_name
    }   
    `;

      // Replace the placeholder in the lambda function template with the actual code
      console.log('Lambda placeholder replacement:', lambda_placeholder_replacement)
      lambdaFunctionTemplate = lambdaFunctionTemplate.replace('// PLACEHOLDER_API_ROUTES_HANDLER', lambda_placeholder_replacement);
    
      return [config, lambdaFunctionTemplate];
    }
