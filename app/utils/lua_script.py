Script = """
local stage_key = KEYS[1]
local count_key = KEYS[2]
local reset_key = KEYS[3]

local now = tonumber(ARGV[1])
local max_stage = tonumber(ARGV[2])

-- rules packed as: count1,duration1,count2,duration2,...
local rules = ARGV

local stage = tonumber(redis.call("GET", stage_key) or "0")
local count = tonumber(redis.call("GET", count_key) or "0")
local reset = tonumber(redis.call("GET", reset_key) or "0")

local idx = stage * 2 + 3
local allowed = tonumber(rules[idx])
local duration = tonumber(rules[idx + 1])

if now > reset then
    count = 0
    reset = now + duration
end

if count >= allowed then
    if stage < max_stage then
        stage = stage + 1
        idx = stage * 2 + 3
        allowed = tonumber(rules[idx])
        duration = tonumber(rules[idx + 1])
        count = 0
        reset = now + duration
    else
        return {0, stage}
    end
end

count = count + 1

redis.call("SET", stage_key, stage)
redis.call("SET", count_key, count)
redis.call("SET", reset_key, reset)

-- Expire everything at the moment the current window ends. Without this the
-- three keys live forever, so every distinct path+identifier combination
-- leaves permanent garbage behind that only FLUSHDB ever reclaims. Advancing a
-- tier rewrites `reset`, so these deadlines track the window in force.
redis.call("EXPIREAT", stage_key, reset)
redis.call("EXPIREAT", count_key, reset)
redis.call("EXPIREAT", reset_key, reset)

return {1, stage}

"""