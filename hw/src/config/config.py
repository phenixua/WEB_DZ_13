# import logging
#
#
# class Config:
#     DB_URL = "postgresql+asyncpg://postgres:567234@localhost:5432/hw_11"
#     LOG_LEVEL = logging.DEBUG
#
#
# config = Config()
from typing import Any

from pydantic import ConfigDict, field_validator, EmailStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DB_URL: str = "postgresql+asyncpg://postgres:567234@localhost:5432/hw_11"
    SECRET_KEY: str = "974790aec4ac460bdc11645decad4dce7c139b7f2982b7428ec44e886ea588c6"
    ALGORITHM: str = "HS256"
    MAIL_USERNAME: EmailStr = "phenixua@meta.ua"
    MAIL_PASSWORD: str = "Phenix4625"
    MAIL_FROM: str = "phenixua@meta.ua"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.meta.ua"
    REDIS_DOMAIN: str = 'localhost'
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    CLOUDINARY_NAME: str = 'abc'
    CLOUDINARY_API_KEY: int = 326488457974591
    CLOUDINARY_API_SECRET: str = "secret"

    # валідація власних параметрів
    @field_validator("ALGORITHM")
    @classmethod
    def validate_algorithm(cls, value: Any):
        if value not in ["HS256", "HS512"]:
            raise ValueError("Algorithm must be HS256 or HS512.")
        return value

    # цей рядок відповідає тому, що раніше було внутри class Settings -> class Config
    # параметр extra='ignore' дуже важливий, бо без нього server-fastAPI буде переходити в crash
    model_config = ConfigDict(extra='ignore', env_file=".env", env_file_encoding="utf-8")  # noqa


config = Settings()