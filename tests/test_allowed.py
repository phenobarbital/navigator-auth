import pytest
from datetime import datetime
from unittest.mock import MagicMock
from navigator_auth.abac.policies import Policy, PolicyEffect, Environment, ActionKey
from navigator_auth.abac.context import EvalContext

# Test Policy
post_policy = Policy(
    'post_articles',
    description="Allowing post actions to Editors",
    effect=PolicyEffect.ALLOW,
    actions=['article:create', 'article:update'],
    resource=["urn:uri:/articles.*$"],
    conditions={
        'method': ['POST', 'PUT', 'PATCH'],
    },
    groups=['editors', 'superusers'],
    priority=2
)

manage_policy = Policy(
    'admin_articles',
    description="Allowing deleting and admin actions to Superusers",
    effect=PolicyEffect.ALLOW,
    actions=['article:delete', 'article:admin'],
    resource=["urn:uri:/articles.*$"],
    conditions={
        'method': ['DELETE', 'POST', 'PUT', 'PATCH'],
    },
    groups=['superusers'],
    priority=3
)

policy = Policy(
    'view_articles',
    description="Allowing view and filter to anyone",
    effect=PolicyEffect.ALLOW,
    actions=['article:view', 'article:filter'],
    resource=["urn:uri:/articles.*$"],
    conditions={
        'method': 'GET',
    },
    priority=1
)


# Creates a mock user object
mock_user = MagicMock()
mock_user.username = 'test@trocglobal.com'
mock_user.user_id = 20
mock_user.email = 'test@trocglobal.com'
mock_user.groups = ['test_group']

# Creates a editor mock user object
mock_editor = MagicMock()
mock_editor.username = 'editor@trocglobal.com'
mock_editor.user_id = 921
mock_editor.email = 'editor@trocglobal.com'
mock_editor.groups = ['editors']

# Creates a mock admin user
mock_admin = MagicMock()
mock_admin.username = 'jlara@trocglobal.com'
mock_admin.user_id = 35
mock_admin.email = 'jlara@trocglobal.com'
mock_admin.groups = ['superusers']

# Creates a mock userinfo object
# Create a mock request object
mock_request = MagicMock()
mock_request.remote = '192.168.1.1'
mock_request.method = 'GET'
mock_request.headers = {'referer': 'http://example.com'}
mock_request.path_qs = '/articles'
mock_request.path = '/articles'
mock_request.rel_url = 'http://example.com/private/some_data'


# Example payload
example_payload = {
    'request': mock_request,
    'user': mock_user,
    'userinfo': {
        'username': 'jlara@trocglobal.com',
        'email': 'jlara@trocglobal.com',
        'groups': mock_user.groups
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
    assert policy.name == 'view_articles'
    assert policy.description == "Allowing view and filter to anyone"
    assert policy.effect == PolicyEffect.ALLOW
    resource = policy.resources[0]
    assert resource.resource_type == 'uri'
    assert resource.namespace == '/articles.*$'
    assert policy.conditions['method'] == 'GET'
    assert policy.actions == [ActionKey('article:view'), ActionKey('article:filter')]

def test_policy_fits():
    _payload = {
        'request': mock_request,
        'user': mock_user,
        'userinfo': {
            'username': 'jlara@trocglobal.com',
            'email': 'jlara@trocglobal.com',
            'groups': mock_user.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **_payload
    )
    fits_result = policy.fits(evt)
    assert fits_result is True
    # check also if policy editor is allowed (for POST)
    evt.method = 'POST'
    fits_result = post_policy.fits(evt)
    assert fits_result is True
    # evt['userinfo']['groups'] = ['test_group']
    fits_result = post_policy.fits(evt)
    assert fits_result is True
    # evt['userinfo']['groups'] = ['superuser']
    fits_result = manage_policy.fits(evt)
    assert fits_result is True


def test_policy_view():
    dummy_context.method = 'GET'
    policy_response = policy.is_allowed(dummy_context, dummy_environment, action='article:view')
    assert policy_response.effect == PolicyEffect.ALLOW

def test_policy_filter():
    dummy_context.method = 'GET'
    policy_response = policy.is_allowed(dummy_context, dummy_environment, action='article:filter')
    assert policy_response.effect == PolicyEffect.ALLOW

def test_policy_publish():
    payload = {
        'request': mock_request,
        'user': mock_editor,
        'userinfo': {
            'username': mock_editor.username,
            'email': mock_editor.email,
            'groups': mock_editor.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'PUT'
    evt.path_qs = '/articles/'
    policy_response = post_policy.is_allowed(evt, dummy_environment, action='article:create')
    assert policy_response.effect == PolicyEffect.ALLOW

def test_policy_post():
    payload = {
        'request': mock_request,
        'user': mock_editor,
        'userinfo': {
            'username': mock_editor.username,
            'email': mock_editor.email,
            'groups': mock_editor.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'POST'
    evt.path_qs = '/articles/1'
    policy_response = post_policy.is_allowed(evt, dummy_environment, action='article:update')
    assert policy_response.effect == PolicyEffect.ALLOW
    ### Checking to another user:
    example_payload['user'] = mock_admin
    example_payload['userinfo']['groups'] = ['superusers']
    dummy_context.method = 'POST'
    dummy_context.path_qs = '/articles/1'
    policy_response = post_policy.is_allowed(dummy_context, dummy_environment, action='article:update')
    assert policy_response.effect == PolicyEffect.ALLOW

def test_policy_delete():
    ## Denied to Editor:
    payload = {
        'request': mock_request,
        'user': mock_editor,
        'userinfo': {
            'username': mock_editor.username,
            'email': mock_editor.email,
            'groups': mock_editor.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'DELETE'
    evt.path_qs = '/articles/1'
    policy_response = manage_policy.is_allowed(evt, dummy_environment, action='article:delete')
    assert policy_response.effect == PolicyEffect.DENY
    ### Checking to Admin User:
    payload = {
        'request': mock_request,
        'user': mock_admin,
        'userinfo': {
            'username': mock_admin.username,
            'email': mock_admin.email,
            'groups': mock_admin.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'DELETE'
    evt.path_qs = '/articles/1'
    policy_response = manage_policy.is_allowed(evt, dummy_environment, action='article:delete')
    assert policy_response.effect == PolicyEffect.ALLOW


def test_policy_admin():
    ## Denied to Editor:
    payload = {
        'request': mock_request,
        'user': mock_editor,
        'userinfo': {
            'username': mock_editor.username,
            'email': mock_editor.email,
            'groups': mock_editor.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'DELETE'
    evt.path_qs = '/articles/1'
    policy_response = manage_policy.is_allowed(evt, dummy_environment, action='article:admin')
    assert policy_response.effect == PolicyEffect.DENY
    ### Checking to Admin User:
    payload = {
        'request': mock_request,
        'user': mock_admin,
        'userinfo': {
            'username': mock_admin.username,
            'email': mock_admin.email,
            'groups': mock_admin.groups
        },
        'session': {
            'id': '1234567890',
            'ip': '192.168.1.1'
        }
    }
    evt = EvalContext(
        **payload
    )
    evt.method = 'DELETE'
    evt.path_qs = '/articles/1'
    policy_response = manage_policy.is_allowed(evt, dummy_environment, action='article:admin')
    assert policy_response.effect == PolicyEffect.ALLOW
