import { Redis } from 'ioredis';
import { config } from './config.js';

let redis: Redis | undefined;

export function getRedis(): Redis {
  if (!redis) {
    redis = new Redis(config.redisUrl, {
      lazyConnect: false,
      maxRetriesPerRequest: 2,
    });

    redis.on('error', (err) => {
      console.error('Redis error:', err.message);
    });
  }

  return redis;
}