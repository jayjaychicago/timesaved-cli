'use client';
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2 } from "lucide-react";


const AWSSetup = () => {
  const [awsCredentials, setAwsCredentials] = useState({
    accessKeyId: 'ACCESS_KEY_ID_PLACEHOLDER',
    secretAccessKey: 'SECRET_ACCESS_KEY_PLACEHOLDER',
    region: 'REGION_PLACEHOLDER'
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
      <h1 className="text-2xl font-bold">Setup an API with Token Authentication and dev Portal</h1>
      <a style={{color:"blue", fontSize:"12px"}} href="https://github.com/jayjaychicago/timesaved-cli">GitHub link</a>

      <form onSubmit={handleSubmit} className="space-y-4" style={{marginTop:"20px"}}>
        <div>
          <label className="block mb-1">Your API Name:</label>
          <Input
            type="text"
            value={applicationName}
            onChange={(e) => setApplicationName(e.target.value)}
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
            'Generate a Terraform script'
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
            <p><strong>Terraform script:</strong> <a
            href="/terraform.zip"
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded ml-2"
          >
            Download Terraform Script
          </a></p>
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