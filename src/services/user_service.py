from datetime import datetime, timezone
from typing import Optional, Tuple, cast

from database import UserGroupEnum
from notifications import EmailSenderInterface
from repositories.user_rep import UserRepository
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    TokenRefreshResponseSchema,
    UserLoginResponseSchema,
    UserRegistrationResponseSchema,
)


class UserService:
    def __init__(
            self,
            repository: UserRepository,
            jwt_manager: Optional[JWTAuthManagerInterface] = None,
            email_sender: Optional[EmailSenderInterface] = None,
    ):
        self.repository = repository
        self.jwt_manager = jwt_manager
        self.email_sender = email_sender

    async def register_user(self, email: str, password: str) -> Tuple[UserRegistrationResponseSchema, str]:
        existing_user = await self.repository.get_user_by_email(email)
        if existing_user:
            raise ValueError(f"A user with this email {email} already exists.")

        user_group = await self.repository.get_user_group(UserGroupEnum.USER)
        if not user_group:
            user_group = await self.repository.create_user_group(UserGroupEnum.USER)

        new_user = await self.repository.create_user(email, password, user_group.id)
        activation_token = await self.repository.create_activation_token(new_user.id)

        if self.email_sender:
            await self.email_sender.send_activation_email(
                new_user.email,
                activation_token.token,
            )

        return UserRegistrationResponseSchema.model_validate(new_user), activation_token.token

    async def login_user(self, email: str, password: str) -> UserLoginResponseSchema:
        user = await self.repository.get_user_by_email(email)
        if not user or not user.verify_password(password):
            raise ValueError("Invalid email or password.")

        if not user.is_active:
            raise ValueError("User account is not activated.")

        jwt_refresh_token = self.jwt_manager.create_refresh_token({"user_id": user.id})
        refresh_token = await self.repository.create_refresh_token(user.id, jwt_refresh_token)

        jwt_access_token = self.jwt_manager.create_access_token({"user_id": user.id})
        return UserLoginResponseSchema(
            access_token=jwt_access_token,
            refresh_token=jwt_refresh_token,
        )

    async def activate_account(self, email: str, token: str) -> None:
        token_record = await self.repository.get_activation_token(email, token)

        now_utc = datetime.now(timezone.utc)
        if (
                not token_record
                or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < now_utc
        ):
            if token_record:
                await self.repository.delete_token(token_record)
            raise ValueError("Invalid or expired activation token.")

        user = token_record.user
        if user.is_active:
            raise ValueError("User account is already active.")

        user.is_active = True
        await self.repository.delete_token(token_record)

    async def refresh_token(self, refresh_token: str) -> TokenRefreshResponseSchema:
        decoded_token = self.jwt_manager.decode_refresh_token(refresh_token)
        user_id = decoded_token.get("user_id")

        refresh_token_record = await self.repository.get_refresh_token(refresh_token)
        if not refresh_token_record:
            raise ValueError("Refresh token not found.")

        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found.")

        new_access_token = self.jwt_manager.create_access_token({"user_id": user_id})
        return TokenRefreshResponseSchema(access_token=new_access_token)

    async def request_password_reset(self, email: str) -> bool:
        user = await self.repository.get_user_by_email(email)

        if not user or not user.is_active:
            return False

        await self.repository.delete_password_reset_tokens(user.id)
        reset_token = await self.repository.create_password_reset_token(user.id)

        if self.email_sender:
            await self.email_sender.send_password_reset_email(email, reset_token.token)

        return True

    async def reset_password(self, email: str, token: str, new_password: str) -> None:
        user = await self.repository.get_user_by_email(email)
        if not user or not user.is_active:
            raise ValueError("Invalid email or token.")

        token_record = await self.repository.get_password_reset_token(user.id)

        if not token_record or token_record.token != token:
            if token_record:
                await self.repository.delete_token(token_record)
            raise ValueError("Invalid email or token.")

        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await self.repository.delete_token(token_record)
            raise ValueError("Invalid email or token.")

        await self.repository.update_user_password(user, new_password)
        await self.repository.delete_token(token_record)
