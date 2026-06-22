import asyncio
from unittest.mock import MagicMock
from aiohttp import web, hdrs
from navigator_auth import AuthHandler
from navigator_auth.conf import exclude_list

async def test_options_exemption():
    print("--- Testing OPTIONS Exemption ---")
    app = web.Application()
    
    # Initialize AuthHandler
    auth = AuthHandler()
    auth.setup(app)
    
    # Create a mock request
    request = MagicMock(spec=web.Request)
    request.method = hdrs.METH_OPTIONS
    request.path = "/api/v1/agents/chat/hr_agent"
    request.match_info = MagicMock()
    request.match_info.route = MagicMock()
    request.get = MagicMock(return_value=False) # request.get('authenticated', False)
    
    # Check verify_exceptions directly
    is_exempt = await auth.verify_exceptions(request)
    print(f"verify_exceptions(OPTIONS): {is_exempt}")
    
    if not is_exempt:
        print("FAILED: OPTIONS request was NOT exempt!")
    else:
        print("SUCCESS: OPTIONS request was exempt.")

    # Test with a non-OPTIONS request for comparison
    request_get = MagicMock(spec=web.Request)
    request_get.method = hdrs.METH_GET
    request_get.path = "/api/v1/agents/chat/hr_agent"
    request_get.match_info = MagicMock()
    request_get.match_info.route = MagicMock()
    request_get.get = MagicMock(return_value=False)
    
    is_exempt_get = await auth.verify_exceptions(request_get)
    print(f"verify_exceptions(GET): {is_exempt_get}")
    
    # Test exclude list
    print(f"Current exclude_list: {exclude_list}")

async def run_middleware_test():
    print("\n--- Testing Auth Middleware with OPTIONS ---")
    app = web.Application()
    auth = AuthHandler()
    auth.setup(app)
    
    async def handler(request):
        return web.Response(text="OK")
    
    request = MagicMock(spec=web.Request)
    request.method = hdrs.METH_OPTIONS
    request.path = "/api/v1/agents/chat/hr_agent"
    request.match_info = MagicMock()
    request.match_info.route = MagicMock()
    request.get = MagicMock(return_value=False) 
    # Mock .app on request for some internal checks if needed
    request.app = app
    
    try:
        response = await auth.auth_middleware(request, handler)
        print(f"Middleware Response: {response}")
        if isinstance(response, web.Response) and response.text == "OK":
             print("SUCCESS: Middleware allowed OPTIONS request.")
        else:
             print(f"FAILURE: Middleware returned unexpected response: {response}")
    except Exception as e:
        print(f"FAILURE: Middleware raised exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_options_exemption())
    asyncio.run(run_middleware_test())
