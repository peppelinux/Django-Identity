https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid#procedura-amministrativa

TODO:
Things to configure for a SPID SP:

- `ForceAuthn="true"` only for L2 and L3;
- NameID Format: `urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified`
- `<ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>` will be instead `<ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>`
- `RequestedAuthnContext` need to be implemented, see: _urn:oasis:names:tc:SAML:2.0:ac:classes: SpidL1_ 
- digest SHA-256 for signing features: *to be implemented in pysaml2*, see [this](https://github.com/IdentityPython/pysaml2/pull/396) -> fixed [here](https://github.com/IdentityPython/pysaml2/pull/597)

 _... continue at page 10 of spid-regole_tecniche_v1.pdf_
