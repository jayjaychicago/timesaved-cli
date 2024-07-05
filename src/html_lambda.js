exports.handler = async (event) => {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate API Token</title>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
</head>
<body>
    <h1>Generate API Token</h1>
    <form id="tokenForm">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <button type="submit">Generate Token</button>
    </form>
    <div id="result"></div>

    <script>
        document.getElementById('tokenForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            try {
                const response = await axios.post('/prod/generate-token', { username });
                const credentials = response.data;
                document.getElementById('result').innerHTML = \`
                    <h2>Your Temporary Credentials:</h2>
                    <p>Access Key ID: \${credentials.AccessKeyId}</p>
                    <p>Secret Access Key: \${credentials.SecretAccessKey}</p>
                    <p>Session Token: \${credentials.SessionToken}</p>
                    <p>Expiration: \${credentials.Expiration}</p>
                \`;
            } catch (error) {
                document.getElementById('result').innerHTML = \`<p>Error: \${error.message}</p>\`;
            }
        });
    </script>
</body>
</html>
    `.trim();

    return {
        statusCode: 200,
        headers: { 'Content-Type': 'text/html' },
        body: html
    };
};