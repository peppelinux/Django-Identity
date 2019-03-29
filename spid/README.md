https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid#procedura-amministrativa

CHECK:
- SP IDSResponse: ricezione delle risposte da parte del Discovery Service. 

DONE:
Things to configure for a SPID SP:

- `ForceAuthn="true"` only for L2 and L3;
   The specification of ForceAuthn=true in the initial SAML request from the service provider specifies that the Identity Provider (IdP) should force re-authentication of the user, even if they possess a valid session
- SP NameID Format in authn request: `urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified` 
  per IDP in authn response (urn:oasis:names:tc:SAML:2.0:nameidformat:transient)
- `<ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>` will be instead `<ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>`
- `RequestedAuthnContext` need to be implemented, see: _urn:oasis:names:tc:SAML:2.0:ac:classes: SpidL1_ 
- digest SHA-256 for signing features: *to be implemented in pysaml2*, see [this](https://github.com/IdentityPython/pysaml2/pull/396) -> fixed [here](https://github.com/IdentityPython/pysaml2/pull/597)

 _... continue at page 10 of spid-regole_tecniche_v1.pdf_

Resources:
- https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/
- https://www.agid.gov.it/sites/default/files/repository_files/circolari/spid-regole_tecniche_v1.pdf
- https://www.spid.gov.it/assets/res/agid-spid-lg-interfacce-informazioni-idp-sp.pdf
- https://github.com/italia/spid
