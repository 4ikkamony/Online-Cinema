from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db

from dependencies.accounts import get_email_notificator, get_jwt_auth_manager
from notifications import EmailSenderInterface
from repositories.user_rep import UserRepository
from security.interfaces import JWTAuthManagerInterface
from services.user_service import UserService


async def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    return UserRepository(db)


async def get_user_service(
    repository: UserRepository = Depends(get_user_repository),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    email_sender: EmailSenderInterface = Depends(get_email_notificator),
) -> UserService:
    return UserService(repository, jwt_manager, email_sender)
