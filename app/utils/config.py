import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    private_key: str | None = os.getenv("PRIVATE_KEY")
    server_private_key: str | None = os.getenv("SERVER_PRIVATE_KEY")
    server_public_key: str | None = os.getenv("SERVER_PUBLIC_KEY")
    jwe_secret: str | None = os.getenv("JWE_SECRET")
    jwe_exp_minutes: int = int(os.getenv("JWE_EXP_MINUTES", "1440"))
    invitation_jws_key: str | None = os.getenv("INVITATION_JWS_KEY")
    salt: str = os.getenv("SALT", "")
    server_id: str = os.getenv("SERVER_ID", "local")


settings = Settings()



