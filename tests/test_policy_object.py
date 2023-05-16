import pytest
from datetime import datetime
from unittest.mock import MagicMock
from navigator_auth.abac.policies import ObjectPolicy, PolicyEffect, Environment
from navigator_auth.abac.context import EvalContext

# Test Object Policy
policy = ObjectPolicy(
    'allowing_widgets_navigator',
    effect=PolicyEffect.ALLOW,
    description="Those widgets from Namespace Navigator are allowed to autenticated users only",
    actions=['widget:view', 'widget:edit', 'widget:delete'],
    resource=[
        "urn:navigator:widget::[123,456,789,1112]"
    ],
    context={
        "is_authenticated": True
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
mock_request.is_authenticated = True
mock_request.headers = {'referer': 'http://example.com'}
mock_request.path_qs = '/private/some_data'
mock_request.path = '/private/some_data'
mock_request.rel_url = 'http://example.com/private/some_data'


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
    },
    'widget': ['123', '892', '8910', '9999', '456']
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
    assert policy.name == 'allowing_widgets_navigator'
    assert policy.description == "Those widgets from Namespace Navigator are allowed to autenticated users only"
    assert policy.effect == PolicyEffect.ALLOW
    resource = policy.resources[0]
    assert resource.resource_type == 'widget'
    assert policy.context == {
        "is_authenticated": True
    }

def test_policy_fits():
    fits_result = policy.fits(dummy_context)
    assert fits_result is True

def test_policy_evaluate():
    evt = EvalContext(
        **example_payload
    )
    policy_response = policy.evaluate(evt, dummy_environment)
    assert policy_response.effect == PolicyEffect.ALLOW
    ### Deny access to non-authenticated users
    evt.is_authenticated = False
    policy_response = policy.evaluate(evt, dummy_environment)
    assert policy_response.effect == PolicyEffect.DENY


def test_policy_filter():
    evt = EvalContext(
        **example_payload
    )
    policy_response = policy._filter(
        objects=['123', '892', '8910', '9999', '456'],
        _type='widget',
        ctx=evt,
        env=dummy_environment
    )
    assert policy_response.effect == PolicyEffect.ALLOW
    assert policy_response.response == ['123', '892', '8910', '9999', '456']
    ### change to filter by resource
    policy.effect = PolicyEffect.DENY
    policy_response = policy._filter(
        objects=['123', '892', '8910', '9999', '456'],
        _type='widget',
        ctx=evt,
        env=dummy_environment
    )
    assert policy_response.effect == PolicyEffect.DENY
    assert policy_response.response == ['892', '8910', '9999']
    ### check for a non-authenticated user
    evt.is_authenticated = False
    policy.effect = PolicyEffect.ALLOW
    policy_response = policy._filter(
        objects=['123', '892', '8910', '9999', '456'],
        _type='widget',
        ctx=evt,
        env=dummy_environment
    )
    assert policy_response.effect == PolicyEffect.ALLOW
    assert policy_response.response == ['892', '8910', '9999']
