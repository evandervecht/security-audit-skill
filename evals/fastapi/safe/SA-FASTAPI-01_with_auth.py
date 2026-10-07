# SA-FASTAPI-01: Endpoint with auth dependency using APIRouter (SAFE)
from fastapi import APIRouter, Depends

router = APIRouter()


async def get_current_user(token: str = Depends(oauth2_scheme)):
    return await verify_token(token)


@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user=Depends(get_current_user)):
    user = await User.get(user_id)
    return user
