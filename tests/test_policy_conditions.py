import pytest
from datetime import datetime
from unittest.mock import MagicMock
from navigator_auth.abac.policies import Policy, PolicyEffect, Environment
from navigator_auth.abac.context import EvalContext

# Test Policy
policy = Policy(
    'grant_view_access',
    effect=PolicyEffect.ALLOW,
    description="This Resource will be accessible by anyone only on GET method.",
    resource=["urn:uri:/public.*$"],
    conditions={
        "method": ["GET"]
    }
)

# Creates a mock user object
mock_user = MagicMock()
mock_user.username = 'jlara@trocglobal.com'
mock_user.user_id = 35
mock_user.email = 'jlara@trocglobal.com'
mock_user.groups = ['superuser']

# Creates a mock userinfo object
# Create a mock request object
mock_request = MagicMock()
mock_request.remote = '192.168.1.1'
mock_request.method = 'GET'
mock_request.headers = {'referer': 'http://example.com'}
mock_request.path_qs = '/public/some_data'
mock_request.path = '/public/some_data'
mock_request.rel_url = 'http://example.com/public/some_data'


# Example payload
example_payload = {
    'request': mock_request,
    'user': mock_user,
    'userinfo': {
        'username': 'jlara@trocglobal.com',
        'email': 'jlara@trocglobal.com',
        'groups': ['test_group']
    },
    'session': {
        'id': '1234567890',
        'ip': '192.168.1.1'
    }
}

# Dummy EvalContext
dummy_context = EvalContext(
    **example_payload
)

# Dummy Environment
current_time = datetime.now()
dummy_environment = Environment(
    hour=current_time.hour,
    day_of_week=current_time.weekday()
)

def test_policy_creation():
    assert policy.name == 'grant_view_access'
    assert policy.effect == PolicyEffect.ALLOW
    assert policy.resources[0].resource_type == 'uri'
    assert policy.resources[0].namespace == '/public.*$'
    assert policy.description == 'This Resource will be accessible by anyone only on GET method.'

def test_policy_fits():
    fits_result = policy.fits(dummy_context)
    assert fits_result is True

def test_policy_evaluate():
    policy_response = policy.evaluate(dummy_context, dummy_environment)
    assert policy_response.effect == PolicyEffect.ALLOW
