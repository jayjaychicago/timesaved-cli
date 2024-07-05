const AWS = require('aws-sdk');
   const sts = new AWS.STS();
   
   exports.handler = async (event) => {
       try {
           const body = JSON.parse(event.body);
           const username = body.username;
   
           const params = {
               DurationSeconds: 3600, // Token valid for 1 hour
               Policy: JSON.stringify({
                   Version: '2012-10-17',
                   Statement: [{
                       Effect: 'Allow',
                       Action: 'execute-api:Invoke',
                       Resource: 'arn:aws:execute-api:*:*:*/*/*/*' // Modify this to restrict to specific API/stage/method
                   }]
               }),
               RoleSessionName: username
           };
   
           const result = await sts.getFederationToken(params).promise();
   
           return {
               statusCode: 200,
               headers: {
                   'Access-Control-Allow-Origin': '*',
                   'Access-Control-Allow-Credentials': true,
               },
               body: JSON.stringify(result.Credentials)
           };
       } catch (error) {
           console.error('Error:', error);
           return {
               statusCode: 500,
               headers: {
                   'Access-Control-Allow-Origin': '*',
                   'Access-Control-Allow-Credentials': true,
               },
               body: JSON.stringify({ error: 'Failed to generate token' })
           };
       }
   };