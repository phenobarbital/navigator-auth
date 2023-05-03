import pytest
from datetime import datetime
from unittest.mock import MagicMock
from navigator_auth.abac.policies import Policy, PolicyEffect, Environment
from navigator_auth.abac.context import EvalContext

# Test Policy
policy = Policy(
    'clone_dashboard_jesus',
    effect=PolicyEffect.ALLOW,
    description="This dashboard can be cloned only username jlara",
    actions=['dashboard:clone'],
    resource=["urn:navigator:dashboard::[12345678,123456789]"],
    context={
        "username": "jlara@trocglobal.com"
    },
    priority=2
)

# Another Test Policy
test_policy = Policy(
    'clone_dashboard',
    effect=PolicyEffect.ALLOW,
    description="Clone dashboards can only by superusers and adv_users, except dashboard:12345678",
    actions=['dashboard:clone'],
    resource=["urn:navigator:dashboard:[!12345678,!123456789]", "urn:navigator:dashboard:*"],
    groups=['superuser', 'adv_users'],
    priority=3

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
        'groups': ['superuser']
    },
    'session': {
        'id': '1234567890',
        'ip': '192.168.1.1'
    },
    "dashboard": ['12345678', '3456']
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
    assert policy.name == 'clone_dashboard_jesus'
    assert policy.effect == PolicyEffect.ALLOW
    assert policy.resources[0].resource_type == 'dashboard'
    assert policy.resources[0].namespace == 'navigator'
    assert policy.resources[0].resource_parts == ['12345678','123456789']
    assert policy.description == 'This dashboard can be cloned only username jlara'
    assert policy.priority == 2

def test_policy_fits():
    fits_result = policy.fits(dummy_context)
    assert fits_result is True

def test_policy_evaluate():
    policy_response = policy.evaluate(dummy_context, dummy_environment)
    assert policy_response.effect == PolicyEffect.ALLOW

def test_other_policy_fits():
    fits_result = test_policy.fits(dummy_context)
    assert fits_result is True

def test_other_policy_evaluate():
    policy_response = test_policy.evaluate(dummy_context, dummy_environment)
    assert policy_response.effect == PolicyEffect.ALLOW
    ## then change user to another group:
    example_payload['userinfo']['groups'] = ['test_group']
    # re-evaluate policy
    policy_response = test_policy.evaluate(dummy_context, dummy_environment)
    assert policy_response.effect == PolicyEffect.DENY
