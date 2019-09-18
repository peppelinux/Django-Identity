## pySAML2 things, improvements and issues

- [time_utils](https://github.com/IdentityPython/pysaml2/issues/445)
- [InResponseTo=""](https://github.com/IdentityPython/pysaml2/issues/458)
- [_parse_request Refactoring](https://github.com/IdentityPython/pysaml2/issues/456)
- [Cookies encrypted in AES CBC](https://github.com/IdentityPython/pysaml2/issues/453)
- [empty URI in ServiceName element](https://github.com/IdentityPython/pysaml2/issues/345)
- [handle_logout_request doesn't sign redirect binding responses as requested](https://github.com/IdentityPython/pysaml2/issues/334)
- [XXE attack](https://github.com/IdentityPython/pysaml2/issues/508)
- [SSRF](https://github.com/IdentityPython/pysaml2/issues/510)

## Advanced Topics
Resources and examples about advanced SAML2 implementations and use cases.

### SAML2 security assertions
- Artifact resolution should be the best auth method in several bandwidth and security aspects. Read [this](https://stackoverflow.com/questions/13616169/what-is-the-purpose-of-a-saml-artifact)

### Auth proxies
- https://github.com/IdentityPython/SATOSA/blob/master/doc/one-to-many.md
- https://github.com/IdentityPython/SATOSA/wiki
- https://github.com/IdentityPython/satosa-developer

My implementation example here:
- https://github.com/peppelinux/Satosa-saml2saml

### WAYF and Discovery-service

This is the leading project regarding Discovery Services:
https://seamlessaccess.org/

My implementation here for SPID/Other federation:
- https://github.com/UniversitaDellaCalabria/unicalDiscoveryService

IdP Discovery Service flow described in [SAML2 specifications](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf?) is made of the following steps:

- SP is configured to use a remote IdP Discovery Service to determine the IdP to be used for the Federation SSO operation
- The SP redirects the user to the IdP Discovery Service via a 302 HTTP redirect and provides the following parameters in the query string
- entityID: the Issuer/ProviderID of OIF/SP
- returnIDParam: the name of the query string parameter that the service needs to use for the parameter containing the IdP - ProviderID value, when redirecting the user back to OIF/SP
- return: the URL to use to redirect the user to OIF/SP
- The service determines the IdP to use
- The service redirects the user to OIF/SP via a 302 HTTP redirect based on the query parameter "return" specified by the SP and provides the following parameters in the query string
- A query parameter containing the the IdP ProviderID value; the name of that query parameter is specified by the SP in the returnIDParam query parameter.

Hopefully a Discovery service will:
- Be aware of a list of known IdPs, referenced by the ProviderID/Issuer identifiers
- Let the user select the IdP to use from a drop down list
- Save the user's choice in a cookie called IDPDiscService
- At runtime, the service will check if the IDPDiscService is present:
- If present and contains a valid IdP, then the service will automatically redirect the user back to the SP with the IdP's - - ProviderID/Issuer: no user interaction will take place
- Otherwise, the service will display a page containing a dropdown list of the known IdPs

Attribute Authorities
- https://www.cesnet.cz/wp-content/uploads/2013/12/saml-aa-shibboleth.pdf

Additional resources:
- https://discovery.refeds.org/guide/
- https://www.switch.ch/aai/support/tools/wayf/
- https://github.com/uktrade/staff-sso
- https://github.com/knaperek/djangosaml2/issues/73
- https://github.com/opennode/waldur-auth-saml2
- https://github.com/IdentityPython/SATOSA/issues/140
- pyFF [Integrated discovery service in part based on RA21.org P3W project](https://pythonhosted.org/pyFF/)

Interesting third-party discovery services:
- http://discojuice.org/getting-started/ - awesome to develop a django app (django-discojuice?). See [this php implementation](https://github.com/andreassolberg/DiscoJuice)
- https://www.accountchooser.com/learnmore.html (OpenID)
- https://github.com/hu-berlin-cms/django-shibboleth-eds


## Resources
- SAML2 Primer on [Wikipedia](https://en.m.wikipedia.org/wiki/SAML_2.0)
- SAML2 Primer for Research & Scholarship on [SAFIRE](https://safire.ac.za/safire/publications/saml-primer/)
- https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html
- [SAML2 Specifications](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- http://djangosaml2idp.readthedocs.io/en/latest/
- https://github.com/IdentityPython
- https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/ (debug)
- https://github.com/SAMLRaider/SAMLRaider (pentest)
- https://wiki.oasis-open.org/security/FrontPage (stdlib source)
- https://www.aleksey.com/xmlsec/download.html (xmlsec1 sources)
