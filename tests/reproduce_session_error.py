import sys
import asyncio
from multidict import CIMultiDictProxy, CIMultiDict
from navigator_session import SessionData
try:
    import orjson
except ImportError:
    import json as orjson

def reproduce():
    # Simulate a session object
    session = SessionData(data={"user_id": 123}, new=False)
    
    # Add a serializable object
    session['foo'] = 'bar'
    
    # Add a non-serializable object (like CIMultiDictProxy from headers)
    # This mimics what might happen if someone does session['headers'] = request.headers
    headers = CIMultiDictProxy(CIMultiDict({'Authorization': 'Bearer ...'}))
    session['headers'] = headers
    
    print(f"Session keys: {list(session.keys())}")
    print(f"Session data (persistent): {session.session_data().keys()}")
    print(f"Session objects (memory only): {session.session_objects().keys()}")
    
    # The problematic code uses dict(session) which merges both
    userdata = dict(session)
    print(f"Userdata keys (dict(session)): {list(userdata.keys())}")
    
    # This should fail if 'headers' is in userdata
    try:
        json_output = orjson.dumps(userdata)
        print("Serialization Successful (Unexpected)")
    except TypeError as e:
        print(f"Serialization Failed as expected: {e}")
    except Exception as e:
        print(f"Serialization Failed with other error: {e}")

    # The fix should use session.session_data()
    print("-" * 20)
    print("Testing Fix (session.session_data()):")
    userdata_fixed = session.session_data()
    try:
        json_output = orjson.dumps(userdata_fixed)
        print("Serialization Successful (Expected with fix)")
    except Exception as e:
        print(f"Fix Failed: {e}")

if __name__ == "__main__":
    reproduce()
