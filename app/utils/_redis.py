import os
import redis.asyncio as aioredis
from typing import Optional


redis_client: Optional[aioredis.Redis] = None

def get_redis_client() ->aioredis.Redis:
    if not redis_client:
        raise RuntimeError("Redis client not initialized")
    return redis_client

async def init_redis_client():
    global redis_client
    if redis_client is not None:
        return redis_client
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis_client = aioredis.from_url(redis_url,
                                    decode_responses= True,
                                    socket_timeout= 40,
                                    max_connections= 1,
                                    health_check_interval= 10
                                    )

    try:
        await redis_client.ping()
    except Exception as e:
        await redis_client.close()
        await redis_client.connection_pool.disconnect()
        redis_client = None
        raise RuntimeError(f"Failed to connect to Redis because {e} from url {redis_url}") from e
    
    return redis_client 


async def close_redis_client() -> None:
    global redis_client
    if redis_client is not None:
        await redis_client.close()
        await redis_client.connection_pool.disconnect()
        redis_client = None

async def get(key:str) -> Optional[str]:
    return await redis_client.get(key)


async def set(key: str, value: str, **kwargs):
    return await redis_client.set(key, value, **kwargs)


async def delete(*keys: str):
    return await redis_client.delete(*keys)


