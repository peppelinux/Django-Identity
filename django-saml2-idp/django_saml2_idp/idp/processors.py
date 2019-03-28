import hashlib
import random

from django.contrib.auth.models import Group
from djangosaml2idp.processors import (BaseProcessor,
                                       NameIdBuilder)
from ldap_peoples.models import LdapAcademiaUser


class GroupProcessor(BaseProcessor):
    """
        Example implementation of access control for users:
        - superusers are allowed
        - staff is allowed
        - they have to belong to a certain group
    """
    group = "ExampleGroup"

    def has_access(self, user):
        return user.is_superuser or \
               user.is_staff or \
               user.groups.filter(name=self.group).exists()


class LdapAcademiaProcessor(BaseProcessor):
    """ Processor class used to retrieve attribute from LDAP server
        and user nameID (userID) with standard formats
    """

    def create_identity(self, user, sp={}):
        """ Generate an identity dictionary of the user based on the
            given mapping of desired user attributes by the SP
        """
        default_mapping = {'username': 'username'}
        sp_mapping = sp['config'].get('attribute_mapping', default_mapping)

        # get ldap user
        lu = LdapAcademiaUser.objects.filter(eduPersonPrincipalName=user.username).first()

        results = {}
        for user_attr, out_attr in sp_mapping.items():
            if hasattr(user, user_attr):
                attr = getattr(user, user_attr)
                results[out_attr] = attr() if callable(attr) else attr

        if not lu:
            return results

        for user_attr, out_attr in sp_mapping.items():
            if hasattr(lu, user_attr):
                attr = getattr(lu, user_attr)
                results[out_attr] = attr() if callable(attr) else attr
        return results
