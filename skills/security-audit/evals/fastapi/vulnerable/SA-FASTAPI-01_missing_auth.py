# SA-FASTAPI-01: Endpoint without auth dependency (VULNERABLE)
from fastapi import FastAPI

app = FastAPI()


@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = await User.get(user_id)
    return user
