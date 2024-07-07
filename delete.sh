#!/bin/bash

# Function to delete existing AWS resources
delete_existing_resources() {
    local application_name="$1"
    local lambda_function_name="${application_name}-lambda"
    local role_name="${lambda_function_name}-role"
    local user_pool_name="${application_name}-user-pool"
    local bucket_name=$(echo "${application_name}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9-]/-/g')-auth-website

    echo "Starting resource deletion process..."

    # Delete CloudFront distribution
    echo "Deleting CloudFront distribution..."
    distribution_id=$(aws cloudfront list-distributions --query "DistributionList.Items[?Comment=='${application_name}'].Id" --output text)
    if [ -n "$distribution_id" ]; then
        etag=$(aws cloudfront get-distribution --id "$distribution_id" --query 'ETag' --output text)
        aws cloudfront delete-distribution --id "$distribution_id" --if-match "$etag"
        echo "Deleted CloudFront distribution: $distribution_id"
    else
        echo "CloudFront distribution not found for application: ${application_name}"
    fi

    # Delete Lambda function
    echo "Deleting Lambda function..."
    aws lambda delete-function --function-name "$lambda_function_name" || echo "Lambda function ${lambda_function_name} not found or already deleted"

    # Delete API Gateway
    echo "Deleting API Gateway..."
    api_id=$(aws apigateway get-rest-apis --query "items[?name=='${application_name}'].id" --output text)
    if [ -n "$api_id" ]; then
        aws apigateway delete-rest-api --rest-api-id "$api_id"
        echo "Deleted API Gateway: ${application_name}"
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

    aws iam delete-role --role-name "$role_name" || echo "Error deleting IAM role ${role_name}"

    # Delete Cognito User Pool
    echo "Deleting Cognito User Pool..."
    user_pool_id=$(aws cognito-idp list-user-pools --max-results 60 --query "UserPools[?Name=='${user_pool_name}'].Id" --output text)
    if [ -n "$user_pool_id" ]; then
        aws cognito-idp delete-user-pool --user-pool-id "$user_pool_id"
        echo "Deleted Cognito User Pool: ${user_pool_name}"
    fi

    # Delete S3 bucket
    echo "Deleting S3 bucket..."
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        aws s3 rm "s3://${bucket_name}" --recursive
        aws s3 rb "s3://${bucket_name}" --force
        echo "Deleted S3 bucket: ${bucket_name}"
    else
        echo "S3 bucket ${bucket_name} not found or already deleted"
    fi

    echo "Resource deletion process completed successfully."
}

# Call the function with the provided application name
delete_existing_resources "terraform2"

