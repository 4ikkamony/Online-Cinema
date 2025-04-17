from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError

from dependencies.users import get_user_service
from exceptions import BaseSecurityError
from schemas import (
    MessageResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from schemas.accounts import (
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
)
from services.user_service import UserService

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="User Registration",
    description="Register a new user with an email and password.",
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "description": "Conflict - User with this email already exists.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A user with this email test@example.com already exists."
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> UserRegistrationResponseSchema:
    try:
        user_response, _ = await user_service.register_user(
            str(user_data.email), user_data.password
        )
        return user_response
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        ) from e


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User Login",
    description="Authenticate a user and return access and refresh tokens.",
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {
            "description": "Unauthorized - Invalid email or password.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or password."}
                }
            },
        },
        403: {
            "description": "Forbidden - User account is not activated.",
            "content": {
                "application/json": {
                    "example": {"detail": "User account is not activated."}
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred while processing the request.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while processing the request."
                    }
                }
            },
        },
    },
)
async def login_user(
        login_data: UserLoginRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> UserLoginResponseSchema:
    try:
        return await user_service.login_user(login_data.email, login_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate User Account",
    description="Activate a user's account using their email and activation token.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The activation token is invalid or expired, "
                           "or the user account is already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid Token",
                            "value": {"detail": "Invalid or expired activation token."},
                        },
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {"detail": "User account is already active."},
                        },
                    }
                }
            },
        },
    },
)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> MessageResponseSchema:
    try:
        await user_service.activate_account(activation_data.email, activation_data.token)
        return MessageResponseSchema(message="User account activated successfully.")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh Access Token",
    description="Refresh the access token using a valid refresh token.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The provided refresh token is invalid or expired.",
            "content": {
                "application/json": {"example": {"detail": "Token has expired."}}
            },
        },
        401: {
            "description": "Unauthorized - Refresh token not found.",
            "content": {
                "application/json": {"example": {"detail": "Refresh token not found."}}
            },
        },
        404: {
            "description": "Not Found - The user associated with the token does not exist.",
            "content": {"application/json": {"example": {"detail": "User not found."}}},
        },
    },
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> TokenRefreshResponseSchema:
    try:
        return await user_service.refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )
    except ValueError as e:
        # Determine the appropriate status code based on the error message
        if "Refresh token not found" in str(e):
            status_code = status.HTTP_401_UNAUTHORIZED
        elif "User not found" in str(e):
            status_code = status.HTTP_404_NOT_FOUND
        else:
            status_code = status.HTTP_400_BAD_REQUEST

        raise HTTPException(status_code=status_code, detail=str(e))


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request Password Reset Token",
    description=(
            "Allows a user to request a password reset token. If the user exists and is active, "
            "a new token will be generated and any existing tokens will be invalidated."
    ),
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
        data: PasswordResetRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> MessageResponseSchema:
    await user_service.request_password_reset(str(data.email))

    # Always return the same message for security reasons
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Reset User Password",
    description="Reset a user's password if a valid token is provided.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": (
                    "Bad Request - The provided email or token is invalid, "
                    "the token has expired, or the user account is not active."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_email_or_token": {
                            "summary": "Invalid Email or Token",
                            "value": {"detail": "Invalid email or token."},
                        },
                        "expired_token": {
                            "summary": "Expired Token",
                            "value": {"detail": "Invalid email or token."},
                        },
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred while resetting the password.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while resetting the password."
                    }
                }
            },
        },
    },
)
async def reset_password(
        data: PasswordResetCompleteRequestSchema,
        user_service: UserService = Depends(get_user_service),
) -> MessageResponseSchema:
    try:
        await user_service.reset_password(data.email, data.token, data.password)
        return MessageResponseSchema(message="Password reset successfully.")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )