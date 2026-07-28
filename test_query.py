import asyncio
import asyncpg

async def run(sql):
    conn = await asyncpg.connect(
        host="127.0.0.1", port=5433,  # the PROXY port, not 5432
        user="postgres", password="postgres", database="testdb",
    )
    try:
        result = await conn.fetch(sql)
        print("Result:", result)
    except Exception as e:
        print("Error:", e)
    finally:
        await conn.close()

if __name__ == "__main__":
    import sys
    sql = " ".join(sys.argv[1:]) or "SELECT count(*) FROM users;"
    asyncio.run(run(sql))
