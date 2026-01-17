from datetime import datetime
import secrets
import logging
import importlib
from typing import Optional
from aiohttp import web
try:
    import redis.asyncio as redis
except ImportError:
    import redis
from navconfig import config
from navigator_auth.conf import (
    REDIS_URL,
    AUTH_USER_MODEL,
    AUTH_PWD_DIGEST,
    AUTH_PWD_ALGORITHM,
    AUTH_PWD_LENGTH
)
from navigator_auth.libs.json import json_decoder
from navigator_auth.exceptions import UserNotFound
from navigator_auth.responses import JSONResponse

class RecoveryTokenStorage:
    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "auth:recovery:"
        self.ttl = 1800  # 30 minutes

    async def save_token(self, token: str, data: dict):
        key = f"{self.prefix}{token}"
        await self.redis.set(key, json_decoder(data), ex=self.ttl)

    async def get_token(self, token: str) -> Optional[dict]:
        key = f"{self.prefix}{token}"
        data = await self.redis.get(key)
        if data:
            try:
                return json_decoder(data)
            except Exception as e:
                logging.error(f"Error decoding recovery token from Redis: {e}")
                return None
        return None

    async def delete_token(self, token: str):
        key = f"{self.prefix}{token}"
        await self.redis.delete(key)

class ForgotPasswordHandler(web.View):
    async def post(self):
        data = await self.request.json()
        email = data.get('email')
        
        if not email:
            return web.HTTPBadRequest(reason="Email is required")

        # Get User Model
        auth = self.request.app['auth']
        user_model = auth.get_usermodel(AUTH_USER_MODEL)
        
        try:
            # Find user by email
            # Assuming asyncdb model
            async with await user_model.filter(email=email) as q:
                user = await q.get()
                
            if not user:
                 # Security: Don't reveal if user exists
                 return JSONResponse({"message": "If the email exists, a recovery link has been sent."}, status=200)
            
            # Generate Token
            token = secrets.token_urlsafe(32)
            
            # Save to Redis
            storage = RecoveryTokenStorage()
            token_data = {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "token": token,
                "created_at": datetime.utcnow().isoformat()
            }
            await storage.save_token(token, token_data)
            
            # Trigger Callback
            callback_path = config.get("FORGOT_PASSWORD_CALLBACK")
            if callback_path:
                try:
                    pkg, module = callback_path.rsplit(".", 1)
                    mod = importlib.import_module(pkg)
                    callback = getattr(mod, module)
                    if asyncio.iscoroutinefunction(callback):
                         await callback(self.request, user, token)
                    else:
                         callback(self.request, user, token)
                except Exception as e:
                    logging.error(f"Error executing forgot password callback: {e}")
                    # Don't fail the request if callback fails, but maybe log it well
            
            return JSONResponse({"message": "If the email exists, a recovery link has been sent."}, status=200)
            
        except Exception as e:
            logging.exception(f"Error in ForgotPasswordHandler: {e}")
            return web.HTTPInternalServerError(reason="Internal Server Error")

import asyncio

class ResetPasswordHandler(web.View):
    async def post(self):
        data = await self.request.json()
        token = data.get('token')
        password = data.get('password')
        confirm_password = data.get('confirm_password') # or request_password
        
        if not token or not password or not confirm_password:
             return web.HTTPBadRequest(reason="Token and passwords are required")
             
        if password != confirm_password:
             return web.HTTPBadRequest(reason="Passwords do not match")
             
        storage = RecoveryTokenStorage()
        token_data = await storage.get_token(token)
        
        if not token_data:
             return web.HTTPBadRequest(reason="Invalid or expired token")
             
        # Optional: Validate user still exists
        auth = self.request.app['auth']
        user_model = auth.get_usermodel(AUTH_USER_MODEL)
        
        try:
             user = await user_model.get(user_id=token_data['user_id'])
             if not user:
                  return web.HTTPBadRequest(reason="User not found")
             
             # Update Password
             try:
                 # Use IdentityProvider to hash password
                 idp = self.request.app['auth']._idp
                 hashed_password = idp.set_password(password)
                 user.password = hashed_password
                 await user.save()
             except Exception as e:
                 logging.error(f"Error setting password: {e}")
                 return web.HTTPInternalServerError(reason="Error updating password")
             
             # Delete token
             await storage.delete_token(token)
             
             return JSONResponse({"message": "Password reset successfully"}, status=200)

        except Exception as e:
             logging.exception(f"Error in ResetPasswordHandler: {e}")
             return web.HTTPInternalServerError(reason="Internal Server Error")
