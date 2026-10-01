import time
from app.utils.lua_script import Script as LUA_SCRIPT
from app.utils._redis import get_redis_client
from fastapi import HTTPException
import time, json, uuid, hashlib
from redis.exceptions import WatchError



# Function that helps get real ip address like x-forwarded-for header for users behind cloudflare or other cdn services can be added here in the future
def get_client_ip(request):
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host
    return ip

class Limiter:
    def __init__(self, redis=None):
        self.redis = redis
        self.script = None
        self.rule_cache = {}

    def _ensure_script(self):
        if self.script is not None:
            return

        if self.redis is None:
            self.redis = get_redis_client()

        self.script = self.redis.register_script(LUA_SCRIPT)

    def parse_rule(self, rule: str):
        if rule in self.rule_cache:
            return self.rule_cache[rule]

        parts = rule.split("_")
        flat = []

        for part in parts:
            count, minutes = part.split("-")
            flat.append(int(count))
            flat.append(int(minutes) * 60)

        self.rule_cache[rule] = flat
        return flat

    def get_identifier(self, request):
        user_id = getattr(request.state, "user_id", None)

        # 🔥 CRITICAL: don't trust user_id for sensitive endpoints
        if user_id and request.url.path not in ("/auth", "/register"):
            return f"user:{user_id}"

        ip = get_client_ip(request)
        ua = request.headers.get("user-agent", "")

        # Must be a stable digest, not the builtin hash(). String hashing is
        # salted per process, so hash(ua) differs between uvicorn workers and
        # across restarts -- which would give every worker its own private
        # counter for the same client and multiply the effective limit by the
        # worker count.
        ua_hash = hashlib.sha256(ua.encode("utf-8")).hexdigest()[:16]

        return f"ip:{ip}:{ua_hash}"

    async def hit(self, rule: str, request, endpoint: str):
        rules = self.parse_rule(rule)
        identifier = self.get_identifier(request)

        base = f"rl:{endpoint}:{identifier}"

        keys = [
            f"{base}:s",
            f"{base}:c",
            f"{base}:r",
        ]

        self._ensure_script()

        now = int(time.time())
        max_stage = (len(rules) // 2) - 1

        result = await self.script(
            keys=keys,
            args=[now, max_stage] + rules
        )

        allowed = bool(result[0])
        stage = int(result[1])

        return allowed, stage
    



def back_off_keys(key: str):
    now = time.time()
    if key == "first":
        return {"trench": 1, "key": "second", "ttl": now + 3 * 60}
    if key == "second":
        return {"trench": 2, "key": "third", "ttl": now + 15 * 60}
    if key == "third":
        return {"trench": 3, "key": "fourth", "ttl": now + 60 * 60}
    if key == "fourth":
        return {"trench": 4, "key": "fifth", "ttl": now + 24 * 3600}
    if key == "fifth":
        return {"trench": 5, "key": "first", "ttl": now + 30}

async def exponential_backoff(redis, phone: str) -> bool:
    backoff_key = f"backoff:{phone}"
    LONG_TTL = 7 * 24 * 3600   # 7 days – only for housekeeping
    retries = 3

    for attempt in range(retries):
        # 1. Watch the key – Redis will abort the transaction if it changes
        await redis.watch(backoff_key)

        # 2. Read current state
        current_raw = await redis.get(backoff_key)
        now = time.time()

        new_data = None
        block_until = None

        if current_raw is None:
            # First request ever – initialise
            new_data = back_off_keys("first")
        else:
            current = json.loads(current_raw)
            if now < current["ttl"]:
                # Still in cooldown – block
                block_until = current["ttl"]
            else:
                # Cooldown expired – advance to the next level
                new_data = back_off_keys(current["key"])

        # 3. If blocking, we did not change anything – just raise and stop
        if block_until is not None:
            remaining = int(block_until - now) + 1
            raise HTTPException(429, f"Too many requests, try again in {round(remaining/60)} minutes")

        # 4. Prepare the transaction
        pipeline = redis.pipeline()
        pipeline.multi()
        pipeline.set(backoff_key, json.dumps(new_data), ex=LONG_TTL)

        try:
            # 5. Execute – if the watched key was modified, WatchError is raised
            await pipeline.execute()
            return True
        except WatchError:
            # Conflict – another request changed the key. Retry.
            continue

    # 6. Fallback (should rarely happen): if all retries fail, do a plain SET
    # This is a best‑effort; for rate‑limiting, occasional double‑advance is acceptable.
    if new_data is None:
        # Re‑read without watch as a last resort
        current_raw = await redis.get(backoff_key)
        if current_raw is None:
            new_data = back_off_keys("first")
        else:
            current = json.loads(current_raw)
            new_data = back_off_keys(current["key"]) if now >= current["ttl"] else back_off_keys("first")
    await redis.set(backoff_key, json.dumps(new_data), ex=LONG_TTL)
    return True







GB = 1024 * 1024 * 1024


UPLOAD_THRESHOLDS = [
    (2 * GB, 5 * 60),      # 2GB -> 5 minutes
    (3 * GB, 10 * 60),     # 3GB -> 10 minutes
    (4 * GB, 20 * 60),     # 4GB -> 20 minutes
    (5 * GB, 30 * 60),     # 5GB -> 30 minutes
]


async def allow_upload(redis, user_id: str, upload_size: int) -> bool:
    """
    Returns True if upload is allowed.
    Returns False if user should try again later.
    """

    now = int(time.time())
    day_ago = now - 86400

    history_key = f"upload:history:{user_id}"
    cooldown_key = f"upload:cooldown:{user_id}"


    # Remove uploads older than 24 hours
    await redis.zremrangebyscore(
        history_key,
        "-inf",
        day_ago
    )


    # Check active cooldown
    cooldown = await redis.ttl(cooldown_key)

    if cooldown > 0:
        return False


    # Get uploads in last 24 hours
    uploads = await redis.zrange(
        history_key,
        0,
        -1
    )


    total = 0

    for item in uploads:
        size = int(item.split(":")[0])
        total += size


    projected = total + upload_size


    # Check if crossing a new threshold
    for threshold, cooldown_seconds in UPLOAD_THRESHOLDS:

        if total < threshold <= projected:

            if cooldown_seconds > 0:
                await redis.setex(
                    cooldown_key,
                    cooldown_seconds,
                    "1"
                )

            break


    # Record upload
    upload_id = str(uuid.uuid4())

    await redis.zadd(
        history_key,
        {
            f"{upload_size}:{upload_id}": now
        }
    )


    # Keep Redis clean
    await redis.expire(
        history_key,
        90000
    )


    return True


async def is_allowed(redis,phone_number: str, ip_address: str) -> tuple[bool, str]:
        """
        Checks if an SMS request is allowed based on Phone and IP limits.
        Returns (True, "Success") or (False, "Error Message").
        """
        current_time = int(time.time())

        # ---------------------------------------------------------------------
        # LAYER 1: RATE LIMIT BY PHONE NUMBER (Max 3 requests per 10 minutes)
        # ---------------------------------------------------------------------
        phone_key = f"sms:limit:phone:{phone_number}"
        
        # Using a Redis pipeline to minimize network roundtrips
        pipe = redis.pipeline()
        pipe.rpush(phone_key, current_time)
        pipe.expire(phone_key, 600)  # Keep key alive for 10 minutes (600s)
        pipe.lrange(phone_key, 0, -1)
        _, _, phone_requests = pipe.execute()

        # Filter out timestamps older than 10 minutes
        valid_phone_requests = [int(t) for t in phone_requests if current_time - int(t) <= 600]
        
        # If the actual list shrank, update it in Redis to clean up memory
        if len(valid_phone_requests) != len(phone_requests):
            redis.delete(phone_key)
            if valid_phone_requests:
                redis.rpush(phone_key, *valid_phone_requests)

        if len(valid_phone_requests) > 3:
            return False, "Too many requests to this phone number. Try again in 10 minutes."

        # ---------------------------------------------------------------------
        # LAYER 2: RATE LIMIT BY IP ADDRESS (Max 5 requests per 1 hour)
        # ---------------------------------------------------------------------
        ip_key = f"sms:limit:ip:{ip_address}"
        
        pipe = redis.pipeline()
        pipe.rpush(ip_key, current_time)
        pipe.expire(ip_key, 3600)  # Keep key alive for 1 hour (3600s)
        pipe.lrange(ip_key, 0, -1)
        _, _, ip_requests = pipe.execute()

        # Filter out timestamps older than 1 hour
        valid_ip_requests = [int(t) for t in ip_requests if current_time - int(t) <= 3600]

        if len(valid_ip_requests) != len(ip_requests):
            redis.delete(ip_key)
            if valid_ip_requests:
                redis.rpush(ip_key, *valid_ip_requests)

        if len(valid_ip_requests) > 5:
            return False, "Too many requests from this device/network. Try again in an hour."

        return True, "Allowed"



