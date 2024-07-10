
function process(resource, method, data, user, grous) {
  console.log('Processing:', resource, method, data, user, grous);
  let result = {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    },
    statusCode: 500,
    body: JSON.stringify({ error: 'No defined process for this resource method combination' })

  };

  // PLACEHOLDER_API_ROUTES_HANDLER
  // Ensure result is defined or properly fetched
  return result;

}

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
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        },
        body: JSON.stringify({ message: 'OPTIONS' , cognitoInfo})
      };
    }
    const resource = "/" + event.resource.replace(/^\//, '');
    const method = event.httpMethod.toLowerCase().toUpperCase();
    const scriptKey = `${resource}:${method}`;
    let data = {};
    if (['GET', 'DELETE','HEAD'].includes(method)) {
      data = event.queryStringParameters;
    } else if (['POST', 'PUT', 'PATCH'].includes(method)) {
      data = JSON.parse(event.body);
    } else {
      // This could either handle more cases or simply return a method not allowed error
      // Here, we handle all other cases as 'Unsupported method' but still allow them to proceed
      return {
        statusCode: 405,
        body: JSON.stringify({ error: 'Method not allowed', cognitoInfo })
      };
    }
  
    let result = process(resource, method, data, cognitoInfo.user, cognitoInfo.groups);     

    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      },
      body: JSON.stringify({ result ,cognitoInfo}) 
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      },
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error', cognitoInfo })

    };
  } finally {
    console.log('Lambda function executed');
  }
};
