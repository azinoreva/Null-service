from pydantic import BaseModel, Field
from typing import Optional, List, Annotated, Literal
from enum import Enum

class Categories(str, Enum):
    # News & Current Affairs
    politics = "politics"
    government = "government"
    law = "law"
    news = "news"
    world = "world"
    local = "local"
    crime = "crime"
    weather = "weather"
    disaster = "disaster"

    # Business & Economy
    business = "business"
    finance = "finance"
    investing = "investing"
    crypto = "crypto"
    markets = "markets"
    startups = "startups"
    economy = "economy"
    real_estate = "real_estate"
    jobs = "jobs"
    career = "career"

    # Tech & Science
    technology = "technology"
    gadgets = "gadgets"
    ai = "ai"
    software = "software"
    cybersecurity = "cybersecurity"
    science = "science"
    space = "space"
    environment = "environment"
    climate = "climate"

    # Health & Lifestyle
    health = "health"
    medicine = "medicine"
    nutrition = "nutrition"
    fitness = "fitness"
    wellness = "wellness"
    mental_health = "mental_health"
    parenting = "parenting"
    relationships = "relationships"
    lifestyle = "lifestyle"

    # Education & Learning
    education = "education"
    academic = "academic"
    learning = "learning"
    books = "books"
    languages = "languages"
    study = "study"
    

    # Entertainment & Culture
    entertainment = "entertainment"
    movies = "movies"
    tv = "tv"
    music = "music"
    art = "art"
    theater = "theater"
    celebrity = "celebrity"
    pop_culture = "pop_culture"

    # Sports
    sports = "sports"
    football = "football"
    basketball = "basketball"
    soccer = "soccer"
    tennis = "tennis"
    motorsports = "motorsports"
    esports = "esports"
    gaming = "gaming"

    # Other Interests
    travel = "travel"
    food = "food"
    cooking = "cooking"
    drinks = "drinks"
    fashion = "fashion"
    beauty = "beauty"
    home_garden = "home_garden"
    diy = "diy"
    automotive = "automotive"
    pets = "pets"
    animals = "animals"
    hobbies = "hobbies"
    photography = "photography"

    # Society
    religion = "religion"
    spirituality = "spirituality"
    social = "social"
    community = "community"
    activism = "activism"
    history = "history"


class Annotations(BaseModel):
    category: Categories
    score: float
    

class Subcategory(BaseModel):
    name: str
    intensity_percent: int = Field(ge=0, le=100)


class Flag(BaseModel):
    name: str
    intensity_percent: int = Field(ge=0, le=100)
    severity_percent: int = Field(ge=0, le=100)
    subcategories: List[Subcategory]


class ContentContext(BaseModel):
    stance: Literal[
        "endorsed",
        "quoted",
        "condemned",
        "educational",
        "fictional",
        "descriptive",
        "unclear"
    ]


class ContentSafetyAnnotation(BaseModel):
    schema_version: Literal["1.0"]
    flags: List[Flag]
    context: ContentContext

class SentAnnotations(BaseModel):
    update_id: str
    user_id:str
    category: Categories # the chosen category that should be swapped to
    annotations: List[Annotations] 
    safety: ContentSafetyAnnotation


class AcknowledgeUpdate(BaseModel):
    update_id: str = Field(..., max_length=40)


# So updates are public, private updates are simply messages sent to everyone on
# updates list while global updates are not encrypted
class Media(BaseModel):
    media_url: str  = Field(..., description="The URL of the media", max_length=400)
    media_type: str  = Field(..., description="The type of the media", max_length=10)
    media_description: str  = Field(..., description="The description of the media", max_length=300)


class updatesModel(BaseModel):
    nickname: str = Field(..., max_length=15, description="The name of the poster")
    media: Optional[Media] = Field(None, description="The media of the update")
    text: str = Field(..., max_length=10000, description="Not encrypted")
    category: Categories
    hashtag: str = Field(..., max_length=100, description="This is a tag that is used to deeply root the categories")


class RequestUpdates(BaseModel):
    user_ids: Optional[List[str]] = Field(None, description="The user IDs to retrieve updates for, this is for people who want to see updates from specific people only and not everyone", max_length=100)
    category: Optional[Categories] = Field(None, description="A single category to filter by")
    categories: Optional[List[Categories]] = Field(None, max_length=50, description="Multiple categories to filter by (used by the feed-control preferences). Omit all filters to get every update.")
    hashtags: Optional[List[Annotated[str, Field(max_length=20)]]] = Field(None, max_length = 10)
    before: Optional[int] = Field(default=0, description="The timestamp before which to retrieve updates", le = 500)
    limit: int = Field(default=20, le=500)


# Return a list of hashtags that are available or trending.
class ReturnListAvailable(BaseModel):
    hashtags: List[str] = Field(..., max_length=50, description="The list of hashtags")


class MarkUpdateRead(BaseModel):
    update_id: str = Field(..., max_length=40)
    like: bool = Field(False, description="If the update has been liked")
    follow: bool = Field(False, description="If the updater has been followed")
    dislike: bool = Field(False, description="If the update has been disliked")
    unfollow: bool = Field(False, description="If the updater has been unfollowed")


class UpdatesResponse(BaseModel):
    update_id: str
    user_id: str
    nickname: Optional[str] = Field(None, description="The name of the poster")
    text: str = Field(..., description="Not encrypted text", max_length=10000)
    expires: int
    media: Optional[Media] = Field(None, description="If the update is media, it is in here")
    annotations: Optional[List[Annotations]] = None
    safety: Optional[ContentSafetyAnnotation] = None
    annotated: bool = False



class UpdateProgress(BaseModel):
    update_id: str
    views: int
    likes: int
    follows: int
    dislikes: int


class Comment(BaseModel):
    update_id: str  = Field(..., max_length=40)
    reply_to: Optional[str] = Field(None, description="This is if the comment is a reply to another comment", max_length=40)  
    at_user: Optional[str] = Field(None, description="This is if the comment is a reply to another comment", max_length=100) 
    nickname: Optional[str] = Field(None, description="The name of the poster", max_length=40) 
    text: str = Field(..., description="Not encrypted text")  


class CommentResponse(BaseModel):
    update_id: str
    comment_id: str
    user_id: str
    nickname: Optional[str] = Field(None, description="The name of the poster")
    text: str = Field(..., description="Not encrypted text")


# Now what happens is that if people keep commenting on a post the time of
# expiration of that post keeps being extended. Else it dies off. This is to
# protect the db from bloating.
class AllComments(BaseModel):
    update_id: str
    comments: List[CommentResponse]