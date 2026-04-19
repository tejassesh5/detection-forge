from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_db(request: Request):
    async with request.app.state.db() as session:
        yield session
