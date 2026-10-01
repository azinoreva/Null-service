import time, json
from app.utils._redis import get_redis_client
from fastapi import HTTPException


def backoff_keys(key:str):
    now = time.time()
    if key == "first":
        return {"trench": 1, "key": "second", "ttl": now + 3*60 }
    if key == "second":
        return {"trench": 2, "key": "third", "ttl": now + 15*60 }
    if key == "third":
        return {"trench": 3, "key": "fourth", "ttl": now + 30*60 }
    if key == "fourth":
        return {"trench": 4, "key": "fifth", "ttl": now + 60*60 }
    if key == "fifth":
        return {"trench": 5, "key": "first", "ttl": now + 24*3600 }
        

async def backoff(redis, phone: str) -> bool:
    backoff_key = f"backoff:{phone}"
    LONG_TTL = 7*24*3600
    retries = 3

    for attempt in range(retries):
        await redis.watch(backoff_key)

        current_raw = await redis.get(backoff_key)
        now=time.time()
        new_data= None
        block_until = None
        if current_raw is None:
            new_data = backoff_keys("first")
        else:
            current_data = json.loads(current_raw)
            if now < current_data["ttl"]:
                block_until = current_data["ttl"]
            else:
                new_data = backoff_keys(current_data["key"])

        if block_until is not None:
            remaining = int(block_until - now) + 1
            raise HTTPException(status_code=429, detail=f"Try again in {remaining} seconds")
        pipeline = redis.pipeline()
        pipeline.multi()
        pipeline.set(backoff_key, json.dumps(new_data), ex=LONG_TTL)

        try:
            await pipeline.execute()
            return True
        except redis.WatchError:
            continue

    if new_data is None:
        current_raw = await redis.get(backoff_key)
        if current_raw is None:
            new_data = backoff_keys("first")
        else:
            current_data = json.loads(current_raw)
            new_data = backoff_keys(current_data["key"]) if now >= current_data["ttl"] else backoff_keys("first")
    
    await redis.set(backoff_key, json.dumps(new_data), ex=LONG_TTL)
    return True


