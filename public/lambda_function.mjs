

export const handler = async (event) => {
  let cognitoInfo = {
    user: null,
    groups: []
  };
  try {
    // Extract Cognito user and groups


    if (event.requestContext && event.requestContext.authorizer && event.requestContext.authorizer.claims) {
      const claims = event.requestContext.authorizer.claims;
      cognitoInfo.user = claims['cognito:username'] || null;
      cognitoInfo.groups = claims['cognito:groups'] ? claims['cognito:groups'].split(',') : [];
    }
    // check event is not null or undefined
    if (!event || !event.resource || !event.httpMethod) {
      console.log('no event, resource of method');
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Bad request', cognitoInfo })
      };
    }
    if (event.httpMethod === 'OPTIONS') {
      return {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
        body: JSON.stringify({ message: 'OPTIONS' , cognitoInfo})
      };
    }
    const resource = event.resource.replace(/^\//, '');
    const method = event.httpMethod.toLowerCase();
    const scriptKey = `${resource}:${method}`;
    let result; 

    // PLACEHOLDER_API_ROUTES_HANDLER
    // Ensure result is defined or properly fetched
    

    return {
      statusCode: 200,
      body: JSON.stringify({ result ,cognitoInfo})
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error', cognitoInfo })

    };
  } finally {
    console.log('Lambda function executed');
  }
};
