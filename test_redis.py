import asyncio
from redis import asyncio as aioredis
from navigator_session.storages.redis import RedisStorage
from navigator_session import SESSION_KEY

async def test():
    conn = aioredis.Redis.from_url('redis://localhost')
    keys = await conn.keys('session:*')
    storage = RedisStorage()
    
    if keys:
        print(f'Found {len(keys)} sessions')
        for key in keys[:5]:
            data = await conn.get(key)
            decoded = storage._decoder(data)
            print(f'Decoded data for {key}:')
            print(decoded)
            print('Has SESSION_KEY?', SESSION_KEY in decoded)
            print('Has "session"?', 'session' in decoded)
    else:
        print('No sessions found in redis.')
    
    await conn.close()

asyncio.run(test())
