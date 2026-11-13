@router.get("/debug/generate-token")
async def debug_generate_token():
    # Only for sandbox testing, remove before production launch
    token = create_access_token(subject="test@example.com")
    return {"access_token": token}