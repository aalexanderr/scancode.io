# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.mixins import UserPassesTestMixin
from django.utils.http import urlencode
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from scancodeio.settings import OIDC_OP_LOGOUT_ENDPOINT, LOGOUT_REDIRECT_URL

def oidc_logout(request):
    logout_url = OIDC_OP_LOGOUT_ENDPOINT
    redirect_uri = request.build_absolute_uri(LOGOUT_REDIRECT_URL)
    return logout_url + '?' + urlencode({'redirect_uri': redirect_uri})

def is_authenticated_when_required(user):
    """
    Returns True if the `user` is authenticated when the
    `SCANCODEIO_REQUIRE_AUTHENTICATION` setting is enabled.

    Always True when the Authentication is not enabled.
    """
    if not settings.SCANCODEIO_REQUIRE_AUTHENTICATION:
        return True

    if user.is_authenticated:
        return True

    return False


def conditional_login_required(function=None):
    """
    Decorator for views that checks that the current user is authenticated when
    authentication is enabled.
    """
    actual_decorator = user_passes_test(is_authenticated_when_required)
    if function:
        return actual_decorator(function)
    return actual_decorator


class ConditionalLoginRequired(UserPassesTestMixin):
    """
    CBV mixin for views that checks that the current user is authenticated when
    authentication is enabled.
    """

    def test_func(self):
        return is_authenticated_when_required(self.request.user)

class OIDCAuthBackend(OIDCAuthenticationBackend):
    def create_user(self, claims):
        user = super(OIDCAuthBackend, self).create_user(claims)
        user.username = claims.get('preferred_username', '')
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        user.email = claims.get('email', '')
        user.save()
        return user

    def update_user(self, user, claims):
        user.username = claims.get('preferred_username', '')
        user.first_name = claims.get('first_name', '')
        user.last_name = claims.get('last_name', '')
        user.email = claims.get('email', '')
        user.save()
        return user

    def filter_users_by_claims(self, claims):
        return super().filter_users_by_claims(claims)