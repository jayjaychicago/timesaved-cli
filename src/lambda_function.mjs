import { createClient } from 'redis';

const redisClient = createClient({
  url: "redis://10.0.0.1:6379",
});

await redisClient.connect();

const luaScripts = {
  'apikey:post': `
    redis.call('SET', KEYS[1], ARGV[1])
    return 'API key set'
  `,
  'apikey:get': `
    return redis.call('GET', KEYS[1])
  `,
  'cancel:post': `
    redis.call('DEL', KEYS[1])
    return 'Operation cancelled'
  `,
  // Add more Lua scripts for other resources and methods as needed
};

export const handler = async (event) => {
  try {
    const resource = event.resource.replace(/^\//, '');
    const method = event.httpMethod.toLowerCase();
    const scriptKey = `${resource}:${method}`;
    
    if (!luaScripts[scriptKey]) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Unsupported operation' }),
      };
    }

    const script = luaScripts[scriptKey];
    const result = await redisClient.eval(script, {
      keys: [event.path],
      arguments: [JSON.stringify(event.body)],
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ result }),
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  } finally {
    await redisClient.disconnect();
  }
};