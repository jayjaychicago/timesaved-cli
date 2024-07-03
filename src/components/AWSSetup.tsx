'use client'

import React, { useState } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Alert, AlertDescription } from "@/components/ui/alert"

const AWSSetup: React.FC = () => {
  const [awsCredentials, setAwsCredentials] = useState({
    accessKeyId: '',
    secretAccessKey: '',
    region: ''
  })
  const [openApiSpec, setOpenApiSpec] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setOutput('')

    try {
      const response = await fetch('/api/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ awsCredentials, openApiSpec }),
      })

      if (!response.ok) throw new Error('Failed to process request')

      const result = await response.json()
      setOutput(result.output)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred')
    }
  }

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">AWS API Gateway Setup</h1>
      <form onSubmit={handleSubmit} className="space-y-4">
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
        <Button type="submit">Generate Terraform</Button>
      </form>
      {error && (
        <Alert variant="destructive" className="mt-4">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {output && (
        <div className="mt-4">
          <h2 className="text-xl font-semibold mb-2">Output:</h2>
          <pre className="bg-gray-100 p-4 rounded overflow-x-auto">{output}</pre>
        </div>
      )}
    </div>
  )
}

export default AWSSetup