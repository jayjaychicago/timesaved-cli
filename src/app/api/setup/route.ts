  import { NextRequest, NextResponse } from 'next/server';
  import yaml from 'js-yaml';
  import AWS from 'aws-sdk';
  import { execSync, exec, spawn } from 'child_process';
  import fs from 'fs';
  import path from 'path';
  import AdmZip from 'adm-zip';
  import { v4 as uuidv4 } from 'uuid';

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


  export async function POST(req: NextRequest) {
    try {
      const { awsCredentials, applicationName, openApiSpec } = await req.json();
      
      if (!awsCredentials || !applicationName || !openApiSpec) {
        throw new Error('Missing AWS credentials, application name, or OpenAPI specification');
      }

      // Read auth.js.tpl and index.html contents
      const authJsTemplate = fs.readFileSync(path.join(process.cwd(), 'public', 'auth_website', 'auth.js.tpl'), 'utf8');
      const indexHtmlTemplate = fs.readFileSync(path.join(process.cwd(), 'public', 'auth_website', 'index.html'), 'utf8');
      
      // Configure AWS SDK
      AWS.config.update({
        accessKeyId: awsCredentials.accessKeyId,
        secretAccessKey: awsCredentials.secretAccessKey,
        region: awsCredentials.region
      });

      const cognito = new AWS.CognitoIdentityServiceProvider({
        apiVersion: '2016-04-18'
      });

      // Delete existing resources
      await deleteExistingResources(applicationName);

      const spec = yaml.load(openApiSpec);
      const terraformConfig = generateTerraformConfig(spec, awsCredentials, applicationName, authJsTemplate, indexHtmlTemplate);
      console.log('Terraform configuration completed.');

      // Create a temporary directory for Terraform files
      const tempDir = `/tmp/terraform-${applicationName}`;
      

      try {
        fs.mkdirSync(tempDir, { recursive: true });
     

        // Write files to the temporary directory
        fs.writeFileSync(path.join(tempDir, 'auth.js.tpl'), authJsTemplate);
        fs.writeFileSync(path.join(tempDir, 'index.html'), indexHtmlTemplate);
        fs.writeFileSync(path.join(tempDir, 'lambda_function.mjs'), fs.readFileSync(path.join(process.cwd(), 'src', 'lambda_function.mjs'), 'utf8'));
        fs.writeFileSync(path.join(tempDir, 'html_lambda.js'), fs.readFileSync(path.join(process.cwd(), 'src', 'html_lambda.js'), 'utf8'));
        fs.writeFileSync(path.join(tempDir, 'token_lambda.js'), fs.readFileSync(path.join(process.cwd(), 'src', 'token_lambda.js'), 'utf8'));

        // Create zip files
        const zip = new AdmZip();
        zip.addLocalFile(path.join(tempDir, 'lambda_function.mjs'));
        zip.writeZip(path.join(tempDir, 'lambda_function.zip'));

        const zip2 = new AdmZip();
        zip2.addLocalFile(path.join(tempDir, 'html_lambda.js'));
        zip2.writeZip(path.join(tempDir, 'html_lambda.zip'));

        const zip3 = new AdmZip();
        zip3.addLocalFile(path.join(tempDir, 'token_lambda.js'));
        zip3.writeZip(path.join(tempDir, 'token_lambda.zip'));

        // Write Terraform configuration to a file
        fs.writeFileSync(path.join(tempDir, 'main.tf'), terraformConfig);
  
        //console.log('Terraform configuration written to main.tf: ',terraformConfig);

      } catch (error) {
        console.error('Error creating temporary directory or writing files:', error);
      } finally {
        console.log('Terraform tempdir completed.');
      }

      // Run Terraform commands
      try {
        console.log('Starting Terraform initialization...');
        const initOutput = await execWithTimeout('terraform init', tempDir, 60000);
        console.log('Terraform initialization output:', initOutput);

        console.log('Starting Terraform plan...');
        const planOutput = await execWithTimeout('terraform plan -out=tfplan', tempDir, 300000);
        console.log('Terraform plan output:', planOutput);

        console.log('Terraform plan contents:');
        const planContents = await execWithTimeout('terraform show tfplan', tempDir, 60000);
        console.log(planContents);

        console.log('Starting Terraform apply...');
        const applyProcess = spawn('terraform', ['apply', '-auto-approve'], { cwd: tempDir });
        
        let applyOutput = '';
        let applyError = '';
        
        applyProcess.stdout.on('data', (data) => {
          const output = data.toString();
          applyOutput += output;
          console.log(`Terraform apply output: ${output}`);
        });
        
        applyProcess.stderr.on('data', (data) => {
          const error = data.toString();
          applyError += error;
          console.error(`Terraform apply error: ${error}`);
        });
        
        const applyExitCode = await new Promise<number>((resolve) => {
          applyProcess.on('close', resolve);
        });
        
        if (applyExitCode !== 0) {
          console.error('Full Terraform apply output:', applyOutput);
          console.error('Full Terraform apply error:', applyError);
          throw new Error(`Terraform apply failed with exit code ${applyExitCode}`);
        }
        
        console.log('Terraform apply completed successfully.');
        console.log('Full Terraform apply output:', applyOutput);
        // Clean up
        console.log('Cleaning up temporary directory...');
       fs.rmSync(tempDir, { recursive: true, force: true });

        console.log('Terraform execution completed successfully.');
        return NextResponse.json({ output: 'Terraform execution completed successfully.' });
      
      } catch (error) {
        console.error('Terraform execution error:', error);
        
        // Log the contents of the Terraform directory
        console.log('Contents of Terraform directory:');
        const dirContents = fs.readdirSync(tempDir);
        console.log(dirContents);

        // If there's a terraform.tfstate file, log its contents
        const tfstatePath = path.join(tempDir, 'terraform.tfstate');
        if (fs.existsSync(tfstatePath)) {
          console.log('Contents of terraform.tfstate:');
          const tfstate = fs.readFileSync(tfstatePath, 'utf8');
          console.log(tfstate);
        }

        // If there's a terraform.tfstate.backup file, log its contents
        const tfstateBackupPath = path.join(tempDir, 'terraform.tfstate.backup');
        if (fs.existsSync(tfstateBackupPath)) {
          console.log('Contents of terraform.tfstate.backup:');
          const tfstateBackup = fs.readFileSync(tfstateBackupPath, 'utf8');
          console.log(tfstateBackup);
        }

        // Clean up
        console.log('Cleaning up temporary directory after error...');
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
    const cognito = new AWS.CognitoIdentityServiceProvider();
    const cloudfront = new AWS.CloudFront();
    const s3 = new AWS.S3();

    const lambdaFunctionName = `${applicationName}-lambda`;
    const roleName = `${lambdaFunctionName}-role`;
    const userPoolName = `${applicationName}-user-pool`;
    const bucketName = `${applicationName.replace(/\s+/g, '-').toLowerCase()}-auth-website`;

    console.log('Starting resource deletion process...');

    // Helper function to handle timeouts
    const withTimeout = (promise, ms, errorMessage) => {
      let timeout = new Promise((_, reject) => {
        let id = setTimeout(() => {
          clearTimeout(id);
          reject(new Error(`Timed out in ${ms}ms: ${errorMessage}`));
        }, ms);
      });

      return Promise.race([
        promise,
        timeout
      ]);
    };

    try {
      console.log('Deleting CloudFront distribution...');
      await withTimeout(
        (async () => {
          const distributions = await cloudfront.listDistributions().promise();
          const distribution = distributions.DistributionList.Items.find(
            item => item.Comment === applicationName
          );
          if (distribution) {
            await cloudfront.deleteDistribution({
              Id: distribution.Id,
              IfMatch: distribution.ETag
            }).promise();
            console.log(`Deleted CloudFront distribution: ${distribution.Id}`);
          } else {
            console.log(`CloudFront distribution not found for application: ${applicationName}`);
          }
        })(),
        300000,
        'CloudFront distribution deletion'
      );

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
          const api = apis.items.find(item => item.name === applicationName);
          if (api) {
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
            for (const policy of attachedPolicies.AttachedPolicies) {
              await iam.detachRolePolicy({
                RoleName: roleName,
                PolicyArn: policy.PolicyArn
              }).promise();
              console.log(`Detached policy ${policy.PolicyArn} from role ${roleName}`);
            }

            const inlinePolicies = await iam.listRolePolicies({ RoleName: roleName }).promise();
            for (const policyName of inlinePolicies.PolicyNames) {
              await iam.deleteRolePolicy({
                RoleName: roleName,
                PolicyName: policyName
              }).promise();
              console.log(`Deleted inline policy ${policyName} from role ${roleName}`);
            }

            await iam.deleteRole({ RoleName: roleName }).promise();
            console.log(`Deleted IAM role: ${roleName}`);
          } catch (error) {
            console.log(`Error deleting IAM role ${roleName}: ${error.message}`);
          }
        })(),
        60000,
        'IAM role deletion'
      );

      console.log('Deleting Cognito User Pool...');
      await withTimeout(
        (async () => {
          const listPoolsResponse = await cognito.listUserPools({ MaxResults: 60 }).promise();
          const userPool = listPoolsResponse.UserPools.find(pool => pool.Name === userPoolName);
          if (userPool) {
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
                Delete: { Objects: objects.Contents.map(({ Key }) => ({ Key })) }
              }).promise();
            }

            await s3.deleteBucket({ Bucket: bucketName }).promise();
            console.log(`Deleted S3 bucket: ${bucketName}`);
          } catch (error) {
            if (error.code !== 'NoSuchBucket') {
              console.log(`Error deleting S3 bucket: ${error.message}`);
            }
          }
        })(),
        60000,
        'S3 bucket deletion'
      );

      console.log('Resource deletion process completed successfully.');
    } catch (error) {
      console.error('Error in deleteExistingResources:', error);
    }
  }

    function generateTerraformConfig(spec: any, awsCredentials: any, applicationName: string, authJsTemplate: string, indexHtmlTemplate: string) {
      const apiName = applicationName.replace(/\s+/g, '-').toLowerCase();
      const lambdaFunctionName = `${apiName}-lambda`;
      const bucketName = `${apiName}-auth-website`;
      console.log('Resource generation begins.');
    

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
      
        index_html_content = replace(local.index_html_template, "{{{user_pool_id}}}", aws_cognito_user_pool.main.id)
        auth_js_content = replace(
          replace(local.auth_js_template, "{{{user_pool_id}}}", aws_cognito_user_pool.main.id),
          "{{{client_id}}}", aws_cognito_user_pool_client.main.id
        )
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
      
      resource "aws_s3_bucket_policy" "website" {
        bucket = aws_s3_bucket.website.id
      
        policy = jsonencode({
          Version = "2012-10-17"
          Statement = [
            {
              Sid       = "PublicReadGetObject"
              Effect    = "Allow"
              Principal = "*"
              Action    = "s3:GetObject"
              Resource  = "S3-\${aws_s3_bucket.website.arn}/*"
            },
          ]
        })
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
      bucket       = aws_s3_bucket.website.id
      key          = "index.html"
      content_type = "text/html"
      content      = local.index_html_content
      etag         = md5(local.index_html_content)
      acl          = "public-read"
    }
    
    resource "aws_s3_object" "auth_js" {
      bucket       = aws_s3_bucket.website.id
      key          = "auth.js"
      content_type = "application/javascript"
      content      = local.auth_js_content
      etag         = md5(local.auth_js_content)
      acl          = "public-read"
    }  
    resource "aws_api_gateway_rest_api" "api" {
      name = "${apiName}"
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
    
        for (const [method, operation] of Object.entries(pathItem)) {
          if (method.toLowerCase() !== 'options') {
            const integrationResourceName = `${resourceName}_${method.toLowerCase()}_${uniqueId}`;
            dependsOnList.push(`aws_api_gateway_integration.${integrationResourceName}`);
    
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
    `;

    
      return config;
    }