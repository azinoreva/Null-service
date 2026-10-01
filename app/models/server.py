from pydantic import BaseModel, Field
from typing import List, Optional
from app.models.updates import Categories
from enum import Enum

class MediaType(Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"

class ServerType(Enum):
    PRIVATE = "private"
    PUBLIC = "public"

class Media(BaseModel):
    url: str = Field(..., max_length = 150)
    size: int = Field(ge=100, le=10000) # in kilobytes
    timer: int = Field(ge=10)# This is the time in minutes the media will be shown fo
    media_type: List[MediaType]

class Server(BaseModel):
    serverId: str
    serverUrl: str
    serverName: str
    media: Optional[Media] = None
    maxPayload: int  # This is the maximum text length allowed for a message going to posts
    colour: str
    about: str
    categories: Optional[List[Categories]] = None
    annotated: bool
    disabled: bool = False
    location: Optional[str]
    serverType: ServerType



    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "serverId": "1234567890",
                "serverName": "Test Server",
                "media": {
                    "url": "https://example.com/image.jpg",
                    "size": 1024,
                    "timer": 10,
                },
                "maxPayload": 1000,
                "colour": "#FFFFFF",
                "about": "This is a test server",
                "categories": ["general"],
                "annotated":False,
                "disabled": False,
                "serverType": ServerType.PRIVATE

            }
        }
    

class ServerIn(BaseModel):
    server_url: str = Field(..., max_length=150)
    serverName: str = Field(..., max_length=100)
    media: Optional[Media] = None
    maxPayload: int = Field(10000, le=100000) # This is the maximum text length allowed for a message going to
    about: str = Field(..., max_length = 500)
    categories: Optional[List[Categories]] = None  # If none, everything goes
    annotated: bool
    disabled: bool = False
    location: Optional[str] =Field (None, max_length=150)
    otp: str = Field(..., max_length = 6, min_length = 6)
    phone: str = Field(..., max_length=16, min_length=12)
    ephemeral: bool
    serverType: ServerType

    