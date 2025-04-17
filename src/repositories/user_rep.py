from typing import Optional
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import UserModel, UserGroupModel, UserGroupEnum, RefreshTokenModel
from database.models import ActivationTokenModel
from database.models.accounts import PasswordResetTokenModel


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_email(self, email: str) -> Optional[UserModel]:
        stmt = select(UserModel).where(UserModel.email == email)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_user_by_id(self, user_id: int) -> Optional[UserModel]:
        stmt = select(UserModel).filter_by(id=user_id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_user_group(self, group_name: UserGroupEnum) -> Optional[UserGroupModel]:
        stmt = select(UserGroupModel).where(UserGroupModel.name == group_name)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def create_user_group(self, group_name: UserGroupEnum) -> UserGroupModel:
        user_group = UserGroupModel(name=group_name)
        self.db.add(user_group)
        await self.db.commit()
        await self.db.refresh(user_group)
        return user_group

    async def create_user(self, email: str, raw_password: str, group_id: int) -> UserModel:
        new_user = UserModel.create(
            email=email,
            raw_password=raw_password,
            group_id=group_id,
        )
        self.db.add(new_user)
        await self.db.flush()
        return new_user

    async def activate_user(self, user: UserModel) -> None:
        user.is_active = True
        await self.db.commit()

    async def create_activation_token(self, user_id: int) -> ActivationTokenModel:
        activation_token = ActivationTokenModel(user_id=user_id)
        self.db.add(activation_token)
        return activation_token

    async def get_activation_token(self, email: str, token: str) -> Optional[ActivationTokenModel]:
        stmt = (
            select(ActivationTokenModel)
            .options(joinedload(ActivationTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == email,
                ActivationTokenModel.token == token,
            )
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def delete_token(self, token) -> None:
        await self.db.delete(token)
        await self.db.commit()

    async def create_refresh_token(self, user_id: int, token: str, days_valid: int = 30) -> RefreshTokenModel:
        refresh_token = RefreshTokenModel.create(
            user_id=user_id, days_valid=days_valid, token=token
        )
        self.db.add(refresh_token)
        await self.db.flush()
        await self.db.commit()
        return refresh_token

    async def get_refresh_token(self, token: str) -> Optional[RefreshTokenModel]:
        stmt = select(RefreshTokenModel).filter_by(token=token)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def delete_password_reset_tokens(self, user_id: int) -> None:
        await self.db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user_id
            )
        )

    async def create_password_reset_token(self, user_id: int) -> PasswordResetTokenModel:
        reset_token = PasswordResetTokenModel(user_id=user_id)
        self.db.add(reset_token)
        await self.db.commit()
        return reset_token

    async def get_password_reset_token(self, user_id: int) -> Optional[PasswordResetTokenModel]:
        stmt = select(PasswordResetTokenModel).filter_by(user_id=user_id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def update_user_password(self, user: UserModel, new_password: str) -> None:
        user.password = new_password
        await self.db.commit()
