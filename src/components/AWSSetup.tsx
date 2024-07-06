'use client';
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2 } from "lucide-react";

const AWSSetup = () => {
  const [awsCredentials, setAwsCredentials] = useState({
    accessKeyId: '',
    secretAccessKey: '',
    region: ''
  });
  const [applicationName, setApplicationName] = useState('');
  const [openApiSpec, setOpenApiSpec] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<any>(null);

  const log = (message: string) => {
    setLogs((prevLogs) => [...prevLogs, message]);
    console.log(message);
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError('');
    setOutput('');
    setLogs([]);
    setResults(null);
    setIsLoading(true);

    try {
      log('Submitting with application name: ' + applicationName);
      
      const response = await fetch('/api/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ awsCredentials, applicationName, openApiSpec }),
      });

      log('Response status: ' + response.status);
      const result = await response.json();
      log('Response body: ' + JSON.stringify(result));

      if (!response.ok) throw new Error(result.error || 'Failed to process request');

      setOutput(result.message);
      setResults(result.outputs);
    } catch (err: unknown) {
      if (err instanceof Error) {
        log('Error in handleSubmit: ' + err);
        setError(err.message);
      } else {
        log('Unknown error in handleSubmit: ' + err);
        setError('An unknown error occurred');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">AWS API Gateway Setup</h1>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block mb-1">Application Name:</label>
          <Input
            type="text"
            value={applicationName}
            onChange={(e) => setApplicationName(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block mb-1">AWS Access Key ID:</label>
          <Input
            type="text"
            value={awsCredentials.accessKeyId}
            onChange={(e) => setAwsCredentials({...awsCredentials, accessKeyId: e.target.value})}
            required
          />
        </div>
        <div>
          <label className="block mb-1">AWS Secret Access Key:</label>
          <Input
            type="password"
            value={awsCredentials.secretAccessKey}
            onChange={(e) => setAwsCredentials({...awsCredentials, secretAccessKey: e.target.value})}
            required
          />
        </div>
        <div>
          <label className="block mb-1">AWS Region:</label>
          <Input
            type="text"
            value={awsCredentials.region}
            onChange={(e) => setAwsCredentials({...awsCredentials, region: e.target.value})}
            required
          />
        </div>
        <div>
          <label className="block mb-1">OpenAPI Specification (YAML):</label>
          <Textarea
            value={openApiSpec}
            onChange={(e) => setOpenApiSpec(e.target.value)}
            required
            rows={10}
          />
        </div>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Processing...
            </>
          ) : (
            'Generate and Apply Terraform'
          )}
        </Button>
      </form>
      {error && (
        <Alert variant="destructive" className="mt-4">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {results && (
        <div className="mt-4">
          <h2 className="text-xl font-semibold mb-2">Results:</h2>
          <div className="bg-gray-100 p-4 rounded overflow-x-auto">
            <p><strong>API URL:</strong> {results.api_url.value}</p>
            <p><strong>Cognito App Client ID:</strong> {results.cognito_app_client_id.value}</p>
            <p><strong>Cognito User Pool ID:</strong> {results.cognito_user_pool_id.value}</p>
            <p><strong>S3 Bucket Website Endpoint:</strong> {results.s3_bucket_website_endpoint.value}</p>
          </div>
        </div>
      )}
      {logs.length > 0 && (
        <div className="mt-4">
          <h2 className="text-xl font-semibold mb-2">Logs:</h2>
          <pre className="bg-gray-100 p-4 rounded overflow-x-auto">
            {logs.map((log, index) => (
              <div key={index}>{log}</div>
            ))}
          </pre>
        </div>
      )}
      {output && (
        <div className="mt-4">
          <h2 className="text-xl font-semibold mb-2">Output:</h2>
          <pre className="bg-gray-100 p-4 rounded overflow-x-auto">{output}</pre>
        </div>
      )}
    </div>
  );
};

export default AWSSetup;