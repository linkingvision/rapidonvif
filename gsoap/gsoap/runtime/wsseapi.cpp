/*
	wsseapi.c

	WS-Security plugin

gSOAP XML Web services tools
Copyright (C) 2000-2010, Robert van Engelen, Genivia Inc., All Rights Reserved.
This part of the software is released under one of the following licenses:
GPL, the gSOAP public license, or Genivia's license for commercial use.
--------------------------------------------------------------------------------
gSOAP public license.

The contents of this file are subject to the gSOAP Public License Version 1.3
(the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.cs.fsu.edu/~engelen/soaplicense.html
Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
for the specific language governing rights and limitations under the License.

The Initial Developer of the Original Code is Robert A. van Engelen.
Copyright (C) 2000-2010, Robert van Engelen, Genivia Inc., All Rights Reserved.
--------------------------------------------------------------------------------
GPL license.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA 02111-1307 USA

Author contact information:
engelen@genivia.com / engelen@acm.org

This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial use license is available from Genivia, Inc., contact@genivia.com
--------------------------------------------------------------------------------
*/

/**

@mainpage

- @ref wsse documents the wsse plugin for WS-Security 1.0 support.
- @ref smdevp documents the smdevp signature/digest engine.
- @ref mecevp documents the mecevp encryption engine.
- @ref threads documents a portable threads and locking API.

*/

/**

@page wsse The wsse WS-Security plugin

@section wsse_5 Security Header

The material in this section relates to the WS-Security specification section 5.

To use the wsse plugin:
-# Run wsdl2h -t typemap.dat on a WSDL of a service that requires WS-Security
   headers. The typemap.dat file is used to recognize and translate Security
   header blocks for XML signature and encryption.
-# Run soapcpp2 on the header file produced by wsdl2h.
-# (Re-)compile stdsoap2.c/pp, dom.c/pp, smdevp.c, mecevp.c, wsseapi.c and the
   generated source files with the -DWITH_DOM and -DWITH_OPENSSL compile flags
   set. The smdevp.c, mecevp.c, and wsseapi.c files are located in the 'plugin'
   directory.
-# Use the wsse plugin API functions described below to add and verify
   Security headers, sign and verify messages, and to encrypt/decrypt messages.

An example wsse client/server application can be found in gsoap/samples/wsse.

The wsse engine is thread safe. However, if HTTPS is required please follow the
instructions in Section @ref wsse_11 to ensure thread-safety of WS-Security
with HTTPS.

The wsse plugin API consists of a set of functions to populate and verify
WS-Security headers and message body content. For more details, we refer to the
following sections that correspond to the WS-Security specification sections:

- Section 6 @ref wsse_6
- Section 7 @ref wsse_7
- Section 8 @ref wsse_8
- Section 9 @ref wsse_9
- Section 10 @ref wsse_10
- @ref wsse_11
- @ref wsse_12
- @ref wsse_13
- @ref wsse_wsc

The basic API is introduced below.

To add an empty Security header block to the SOAP header, use:

@code
    soap_wsse_add_Security(soap);
@endcode

To delete a Security header, use:

@code
    soap_wsse_delete_Security(soap);
@endcode

Adding an empty Security header block is not very useful. In the following, we
present the higher-level functions of the wsse plugin to populate and verify
Security header content.

Note: The soap context includes an actor value soap.actor that is populated and
rendered as the SOAP-ENV:actor (SOAP 1.1) or SOAP-ENV:role (SOAP 1.2) attribute
in XML within the generic SOAP Header. The attribute is optional, but should be
used to target a recipient such as an intermediate node to process the SOAP
header.  In contrast, actor or role attributes within Security header blocks
target specific recipients to process the Security header block. The gSOAP
implementation does not automate this feature and application should set and
check the actor/role attribute when necessary. In addition, the current
implementation supports the inclusion of a single Security header block in the
SOAP header.

To populate the SOAP-ENV:actor or SOAP-ENV:role attribute within the Security
header, use:

@code
    soap_wsse_add_Security_actor(soap, "recipient");
@endcode

To obtain the actor or role value (e.g. after receiving a message), use:

@code
    _wsse__Security *security = soap_wsse_Security(soap);
    if (security)
    { ... = security->SOAP_ENV__actor; // SOAP 1.1
      ... = security->SOAP_ENV__role;  // SOAP 1.2
@endcode

The SOAP-ENV:mustUnderstand attribute is automatically added and checked by the
gSOAP engine. A gSOAP application compiled without Security support will reject
Security headers.

Security header blocks are attached to the soap context, which means that the
information will be automatically kept to support multiple invocations.

@section wsse_6 Security Tokens

The material in this section relates to the WS-Security specification section 6.

@subsection wsse_6_2 User Name Token

To add a user name token to the Security header block, use:

@code
    soap_wsse_add_UsernameTokenText(soap, "Id", "username", NULL);
@endcode

The Id value is optional. When non-NULL the user name token is included in the
digital signature to protect its integrity. It is common for the wsse plugin
functions to accept such Ids, which are serialized as wsu:Id identifiers for
cross-referencing XML elements. The signature engine of the wsse plugin is
designed to automatically sign all wsu:Id attributed elements to simplify the
code you need to write to implement the signing process.

To add a user name token with clear text password, use:

@code
    soap_wsse_add_UsernameTokenText(soap, "Id", "username", "password");
@endcode

It is strongly recommended to use @ref soap_wsse_add_UsernameTokenText only in
combination with HTTPS encrypted transmission or not at all. A better
alternative is to use password digests. With password digest authentication,
the digest value of a password (with message creation time and a random nonce)
is compared on both sides, thus eliminating the need to exchange a password
over the wire.

To add a user name token with password digest, use:

@code
    soap_wsse_add_UsernameTokenDigest(soap, "Id", "username", "password");
@endcode

Although the password string is passed to this function, it is not rendered in
XML or stored in a message log. It has been argued that this approach adopted
by the WS-Security protocol is still vulnerable since the application retrieves
the password in text form requiring a database to store passwords in clear
text. However, a digest algorithm can be used to hash the passwords and store
their digests instead, which eliminates the need to store clear-text passwords.
Note that this is a common approach adopted by Unix for decades.

By setting the Id value to a unique string, the user name token is also
digitally signed by the signature engine further preventing tampering with its
value.

You must use @ref soap_wsse_add_UsernameTokenDigest for each message exchange
to refresh the password digest even when the user name and password are not
changed. Otherwise, the receiver might flag the message as a replay attack.

Clear-text passwords and password digests are verified with
@ref soap_wsse_verify_Password. To verify a password at the receiving side to
authorize a request (e.g. within a Web service operation), use:

@code
    int ns__myMethod(struct soap *soap, ...)
    { const char *username = soap_wsse_get_Username(soap);
      const char *password;
      if (!username)
        return soap->error; // no username: return FailedAuthentication
      password = ...; // lookup password of username
      if (soap_wsse_verify_Password(soap, password))
        return soap->error; // password verification failed: return FailedAuthentication
      ... // process request, then sign the response message:
      if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
       || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
       || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0)
        return soap->error;
      return SOAP_OK;
    }
@endcode

Note that the @ref soap_wsse_get_Username functions sets the
wsse:FailedAuthentication fault. It is common for the wsse plugin functions to
return SOAP_OK or a wsse fault that should be passed to the sender by returning
soap->error from service operations. The fault is displayed with the
soap_print_fault() function.

Password digest authentication prevents message replay attacks. The wsse plugin
keeps a database of password digests to thwart replay attacks. This is the
only part in the plugin code that requires mutex provided by threads.h.  Of
course, this only works correctly if the server is persistent, such as a
stand-alone service. Note that CGI-based services do not keep state. Machine
clocks must be synchronized and clock skew should not exceed @ref
SOAP_WSSE_CLKSKEW at the server side.

@subsection wsse_6_3 Binary Security Tokens

X509 certificates are commonly included in Security header blocks as binary
security tokens. A certificate is used to verify the digital signature of a
digitally signed message using the public key embedded within the certificate.
The certificate itself is signed by a certificate authority (CA) that vouches
for the authenticity of the certificate, i.e. to prove the identify of the
message originator. This verification process is important, because digital
signatures are useless without verification: an attacker could simply replace
the message, sign it, and replace the certificate.

Certificates are automatically verified by the wsse plugin signature engine
when received and accessed, which means that the certificates of the CAs must
be made accessible to the wsse plugin as follows:

@code
    soap->cafile = "cacerts.pem";  // use this
    soap->capath = "dir/to/certs"; // and/or point to CA certs
    soap->crlfile = "revoked.pem"; // use CRL (optional)
@endcode

The @ref soap_wsse_verify_X509 function checks the validity of a certificate.
The check is automatically performed. The check is also performed when
retrieving the certificate from a Security header block, either automatically
by the wsse plugin's signature verification engine or manually as follows:

@code
    X509 *cert = soap_wsse_get_BinarySecurityTokenX509(soap, "Id");
@endcode

where Id is the identification string of the binary security token or NULL.

The verification is an expensive process that will be optimized in future
releases by caching the certificate chain.

To attach a binary security token stored in a PEM file to a Security header
block for transmission, use:

@code
    soap_wsse_add_BinarySecurityTokenPEM(soap, NULL, "mycert.pem")
@endcode

A binary security token can be automatically signed by setting its Id
attribute:

@code
    soap_wsse_add_BinarySecurityTokenPEM(soap, "X509Token", "mycert.pem")
@endcode

Repeatedly loading a certificate from a PEM file is inefficient. To reuse a
certificate loaded from a PEM file for multiple invocations, use:

@code
    FILE *fd = fopen("mycert.pem", "r");
    X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert))
      ... // an error occurred
@endcode

Other types of binary security tokens can be added to the Security header block using:

@code
    soap_wsse_add_BinarySecurityToken(soap, "Id", "valueType", data, datalen);
@endcode

@section wsse_6_4 XML Tokens

The use and processing rules for XML tokens such as SAML assertions is specific
to an application.  The wsse plugin does not automate the use of XML tokens.
The developer is encouraged to generate code for the SAML schema with wsdl2h
and add the necessary assertions to the Security header block:

@code
typedef struct _wsse__Security
{       struct _wsu__Timestamp*                 wsu__Timestamp;
        struct _wsse__UsernameToken*            UsernameToken;
        struct _wsse__BinarySecurityToken*      BinarySecurityToken;
        struct _saml__Assertion*		saml__Assertion; // added
	struct xenc__EncryptedKeyType*          xenc__EncryptedKey;
        struct ds__SignatureType*               ds__Signature;
        @char*                                  SOAP_ENV__actor;
        @char*                                  SOAP_ENV__role;
} _wsse__Security;
@endcode

Alternatively, a DOM can be used to store and retrieve XML tokens:

@code
#import "dom.h"
typedef struct _wsse__Security
{       struct _wsu__Timestamp*                 wsu__Timestamp;
        struct _wsse__UsernameToken*            UsernameToken;
        struct _wsse__BinarySecurityToken*      BinarySecurityToken;
	struct xenc__EncryptedKeyType*          xenc__EncryptedKey;
        struct ds__SignatureType*               ds__Signature;
        int					__size;
        xsd__anyType*				any;
        @char*                                  SOAP_ENV__actor;
        @char*                                  SOAP_ENV__role;
} _wsse__Security;
@endcode

@section wsse_7 Token References

The material in this section relates to the WS-Security specification section 7.

To use a certificate for signature verification, add a direct security token
reference URI for the token to the KeyInfo, for example:

@code
    soap_wsse_add_KeyInfo_SecurityTokenReferenceURI(soap, "URI", "valueType");
@endcode

and:

@code
    soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "URI");
@endcode

For X509 certificates we use this to add a binary security token with the
certificate and a reference to the local token:

@code
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token"))
      ... // an error occurred
@endcode

This follows the recommended practice to place Security token references in
the KeyInfo element of a Signature. The KeyInfo is used to verify the validity
of a signature value.

Key identifiers can be used as well:

@code
    soap_wsse_add_KeyInfo_SecurityTokenReferenceKeyIdentifier(soap, "Id", "valueType", data, datalen);
@endcode

Embedded references are added with:

@code
    soap_wsse_add_KeyInfo_SecurityTokenReferenceEmbedded(soap, "Id", "valueType");
@endcode

Full support for embedded references requires coding to add tokens and
assertions, as well as to consume embedded references at the receiving side.
There is no automated mechanism to take the embedded references and process
them accordingly.

The use of key names is not recommended, but in case they are required they can
be added with:

@code
    soap_wsse_add_KeyInfo_KeyName(soap, "name");
@endcode

@section wsse_8 Signatures

The material in this section relates to the WS-Security specification section 8.

The wsse plugin must be registered to sign and verify messages:

@code
    soap_register_plugin(soap, soap_wsse);
@endcode

XML signatures are usually computed over normalized XML (to ensure the XML
processors of intermediate nodes can accurately reproduce the XML). To this
end, the exclusive canonical XML standard (exc-c14n) is required, which is set
using the SOAP_XML_CANONICAL flag:

@code
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL);
    soap_register_plugin(soap, soap_wsse);
@endcode

If you prefer XML indentation, use:

@code
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
@endcode

Other flags to consider:

- SOAP_IO_CHUNK for HTTP chunked content to stream messages.
- SOAP_ENC_GZIP for HTTP compression (also enables HTTP chunking).

Next, we decide which signature algorithm is appropriate to use:
- HMAC-SHA uses a secret key (also known as a shared key in symmetric
  cryptography) to sign the SHA digest of the SignedInfo element.
- DSA-SHA uses a DSA private key to sign the SHA digest of the SignedInfo
  element.
- RSA-SHA uses a RSA private key to sign the SHA digest of the SignedInfo
  element.

HMAC-SHA is the simplest method, but relies on the fact that you have to make
absolutely sure the key is kept secret on both the sending and receiving side.
As long as the secret key is confidential, messages are securely signed.
However, this is virtually impossible when exchanging messages with untrusted
disparate parties. The advantage of HMAC-SHA is the speed by which messages
are signed and verified.

Algorithms HMAC SHA1, SHA256, and SHA512 are supported:
- @ref SOAP_SMD_HMAC_SHA1	http://www.w3.org/2000/09/xmldsig#hmac-sha1
- @ref SOAP_SMD_HMAC_SHA256	http://www.w3.org/2001/04/xmldsig-more#hmac-sha256
- @ref SOAP_SMD_HMAC_SHA512	http://www.w3.org/2001/04/xmldsig-more#hmac-sha512

DSA-SHA and RSA-SHA rely on public key cryptography. In simplified terms, a
message is signed using the (confidential!) private key. The public key is used
to verify the signature. Since only the originating party could have used its
private key to sign the message, the integrity of the message is guaranteed. Of
course, we must trust the public key came from the originator (it is often
included as an X509 certificate in the message). To this end, a trusted
certificate authority should have signed the public key, thereby creating a
X509 certificate that contains the public key and the identity of the message
originator.

Algorithms DSA-SHA1, RSA-SHA1, RSA-SHA256, and RSA-SHA512 are supported:
- @ref SOAP_SMD_SIGN_DSA_SHA1	http://www.w3.org/2000/09/xmldsig#dsa-sha1
- @ref SOAP_SMD_SIGN_RSA_SHA1	http://www.w3.org/2000/09/xmldsig#rsa-sha1
- @ref SOAP_SMD_SIGN_RSA_SHA256	http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
- @ref SOAP_SMD_SIGN_RSA_SHA512	http://www.w3.org/2001/04/xmldsig-more#rsa-sha512

An optional callback function can be passed to the plugin that is responsible
for providing a certificate or key to the wsse engine to verify a signed
message. For example, when a security token is absent from an DSA-SHA or
RSA-SHA signed message then the only mechanism to automatically verify the
signature is to let the callback produce a certificate:

@code
    soap_register_plugin_arg(soap, soap_wsse, security_token_handler);

    const void *security_token_handler(struct soap *soap, int *alg, const char *keyname, int *keylen)
    { // Note: 'keyname' argument is may be used with shared secret key
      // decryption where the keyname is from the ds:KeyInfo/KeyName content
      if (keyname)
      { ... lookup keyname ...
	const void *key = ...;
	*keylen = ...;
        *alg = ...;
	return key;
      }
      // Get the user name from UsernameToken in message
      const char *uid = soap_wsse_get_Username(soap);
      switch (*alg)
      { case SOAP_SMD_VRFY_DSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA256:
        case SOAP_SMD_VRFY_RSA_SHA512:
          if (uid)
          { // Lookup uid to retrieve the X509 certificate to verify the signature
            const X509 *cert = ...; 
            return (const void*)cert;
          }
          return NULL; // no certificate: fail
        case SOAP_SMD_HMAC_SHA256:
          if (uid)
          { // Lookup uid to retrieve the HMAC SHA256 key to verify the signature
            const void *key = ...; 
	    *alg = ...;
	    *keylen = ...;
            return key;
          }
          return NULL; // no certificate: fail
        case SOAP_MEC_ENV_DEC_DES_CBC:
        case SOAP_MEC_ENV_DEC_AES128_CBC:
        case SOAP_MEC_ENV_DEC_AES256_CBC:
        case SOAP_MEC_ENV_DEC_AES512_CBC:
	  // return decryption private key associated with keyname
        case SOAP_MEC_DEC_DES_CBC:
        case SOAP_MEC_DEC_AES128_CBC:
        case SOAP_MEC_DEC_AES256_CBC:
        case SOAP_MEC_DEC_AES512_CBC:
	  // *keylen = ...
	  // return decryption shared secret key associated with keyname
      }
      return NULL; // fail
    }
@endcode

@subsection wsse_8_2a Signing Messages

After the plugin is registered and a signature algorithm selected, the
@ref soap_wsse_sign function or the @ref soap_wsse_sign_body function is used
to initiate the signature engine to automatically sign outbound messages.

The code to sign the SOAP Body of a message using HMAC-SHA1 is:

@code
    static char hmac_key[16] =
    { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    if (soap_wsse_sign_body(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key))
      ... // an error occurred
    else if (soap_call_ns__myMethod(soap, ...))
      ... // a transmission error occurred
@endcode

The hmac_key is some secret key you generated for the sending side and
receiving side (don't use the one shown here). Instead of SHA1, SHA256 and
SHA512 hashes can be used.

As always, use soap_print_fault() to display the error message.

To sign the body of an outbound SOAP message using RSA-SHA (DSA-SHA is
similar), we include the X509 certificate with the public key as a
BinarySecurityToken in the header and a KeyInfo reference to the token to let
receivers use the public key in the certificate to verify the authenticity of
the message:

@code
    FILE *fd;
    EVP_PKEY *rsa_private_key;
    X509 *cert;
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    fd = fopen("privkey.pem", "r");
    rsa_private_key = PEM_read_PrivateKey(fd, NULL, NULL, "password");
    fclose(fd);
    fd = fopen("cert.pem", "r");
    X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
     || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0))
      ... // an error occurred
    else if (soap_call_ns__myMethod(soap, ...))
      ... // a transmission error occurred
@endcode

The private key and its certificate are often placed in the same file, see e.g.
server.pem in the package.

To summarize the signing process:
-# Register the wsse plugin.
-# Obtain an HMAC secret key or a DSA or RSA private key.
-# For DSA or RSA, obtain the X509 certificate with the public key signed by a
   certificate authority.
-# Add the X509 certificate as a BinarySecurityToken to the header.
-# Add a KeyInfo BinarySecurityTokenReference.
-# Invoke @ref soap_wsse_sign or @ref soap_wsse_sign_body to sign the message.
-# Always check the function return values for errors. You don't want to
   produce and accept messages with an invalid Security headers.

@subsection wsse_8_2b Signing Message Parts

The @ref soap_wsse_sign_body function signs the entire SOAP body. If it is
desirable to sign individual parts of a message the @ref soap_wsse_sign
function should be used. All message parts with wsu:Id attributes are signed.
These message parts should not be nested (nested elements will not be
separately signed). By default, all and only those XML elements with wsu:Id
attributes are signed. Therefore, the wsu:Id attribute values used in a message
must be unique within the message. Although usually not required, the default
signing rule can be overridden with the @ref soap_wsse_sign_only function, see
@ref wsse_8_3.

For example, consider a transaction in which we only want to sign a contract in
the SOAP Body. This allows us to modify the rest of the message or extract the
contract in XML and pass it on with the signature.

The gSOAP header file includes a myContract declaration:

@code
    struct ns__myContract
    { @char* wsu__Id = "Contract";
      char* name;
      char* title;
      char* terms;
    };
    int ns__myMethod(struct ns__myContract agreement, bool* accepted);
@endcode

The default value of the wsu:Id is "Contract" so that we can instantiate the
struct, automatically sign it, and send it as follows:

@code
    struct ns__myContract contract;
    bool accept;
    soap_default_ns__myContract(soap, &contract);
    contract.name = ...;
    contract.title = ...;
    contract.terms = ...;
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
     || soap_wsse_sign(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0))
      ... // an error occurred
    else if (soap_call_ns__myMethod(soap, contract, &accept))
      ... // a transmission error occurred
@endcode

The above example shows a wsu:Id attribute embedded (hardcoded) in a struct.
When it is not possible to add the wsu__Id member, for example when the type is
a string instead of a struct, it is suggested to specify the XML element to be
signed with the @ref soap_wsse_set_wsu_id(soap, "space-separated string of
element names") function. Use it before each call or in the server operation
(when returning XML data from a service operation). This lets the engine add
wsu:Id="tag" attribute-value pair to the element's tag name. For example:

@code
    soap_wsse_set_wsu_id(soap, "ns:myContract"); // <ns:myContract wsu:Id="ns:myContract">...
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
     || soap_wsse_sign(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0))
      ... // an error occurred
    soap_wsse_set_wsu_id(soap, NULL);
@endcode

This code adds the wsu:Id="ns-myContract" to the ns:myContract element. Here,
the wsu__Id value in the struct MUST NOT be set. Otherwise, two wsu:Id
attributes are present which is invalid. Also, the element signed must be
unique in the message. That is, there cannot be more than one matching element,
otherwise the resulting signature is invalid.

Note: to reset the automatic wsu:Id attributes addition, pass NULL to
@ref soap_wsse_set_wsu_id as shown above. This is automatically performed when
a new message is received (but not automatically in a sequence of one-way sends
for example).

WARNING:
When signing parts of the body as outlined above, use @ref soap_wsse_sign
(do NOT use @ref soap_wsse_sign_body).

WARNING:
Do not attempt to sign an element with a wsu:Id that is a subelement of another
element with a wsu:Id, that is, do not sign inner nested wsu:Id elements. The
element that you will try to sign will not be canonicalized and will lead to a
failure of the signature verification. When elements with wsu:Id are nested,
sign the outermost element.

We recommend to sign the entire SOAP Body using soap_wsse_sign_body and
reserve the use of soap_wsse_set_wsu_id for SOAP Header elements, such as
WS-Addressing elements. For example:

@code
    #include "wsaapi.h"
    ...
    soap_wsa_request(soap, RequestMessageID, ToAddress, RequestAction);
    soap_wsse_set_wsu_id(soap, "wsa5:To wsa5:From wsa5:ReplyTo wsa5:Action");
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
     || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0))
      ... // an error occurred
    else if (soap_call_ns__myMethod(soap, ...))
      ... // a transmission error occurred
    soap_wsse_set_wsu_id(soap, NULL);
@endcode

This code signs the wsa5:To and wsa5:Action SOAP header elements (set with
soap_wsa_request, see the WS-Addressing "wsa" API in the gSOAP documentation
for more information on the use of WS-Addressing). It is fine to specify more
elements with @ref soap_wsse_set_wsu_id than actually present in the XML
payload. The other WS-Addressing headers are not present and are not signed.

WARNING:
@ref soap_wsse_set_wsu_id should only be set once for each @ref soap_wsse_sign
or @ref soap_wsse_sign_body. Each new call overrides the previous setting.

WARNING:
Never use @ref soap_wsse_set_wsu_id to set the wsu:Id for an element that
occurs more than once in the payload, since each will have the same wsu:Id
attribute that may lead to a WS-Signature failure.

@subsection wsse_8_3 Signing Tokens

To sign security tokens such as user names, passwords, and binary security
tokens, just assign their Id values with a unique string, such as "Time" for
timestamps and "User" for user names. For example:

@code
    soap_wsse_add_Timestamp(soap, "Time", 600);
    soap_wsse_add_UsernameTokenDigest(soap, "User", "username", "password");
    ... // the rest of the signing code
@endcode

Note that by default all wsu:Id-attributed elements are signed. To filter a
subset of wsu:Id-attributed elements for signatures, use the
@ref soap_wsse_sign_only function as follows:

@code
    soap_wsse_add_UsernameTokenDigest(soap, "User", "username", "password");
    soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
    soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0);
    soap_wsse_sign_only(soap, "User Body");
@endcode

Note that in the above we MUST set the X509Token name for cross-referencing
with a wsu:Id, which normally results in automatically signing that token
unless filtered out with @ref soap_wsse_sign_only. The SOAP Body wsu:Id is
always "Body" and should be part of the @ref soap_wsse_sign_only set of wsu:Id
names to sign.

When using @ref soap_wsse_set_wsu_id we need to use the tag name with
@ref soap_wsse_sign_only. For example:

@code
    soap_wsa_request(soap, RequestMessageID, ToAddress, RequestAction);
    soap_wsse_set_wsu_id(soap, "wsa5:To wsa5:From wsa5:ReplyTo wsa5:Action");
    soap_wsse_add_UsernameTokenDigest(soap, "User", "username", "password");
    soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
    soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0);
    soap_wsse_sign_only(soap, "wsa5:To wsa5:From wsa5:ReplyTo wsa5:Action User Body");
@endcode

Note: @ref soap_wsse_sign_only should only be set once for each @ref
soap_wsse_sign or @ref soap_wsse_sign_body. Each new call overrides the
previous.

Note: to reset the filtering of signed tokens and elements, pass NULL to
@ref soap_wsse_sign_only. This is automatically performed when a new message is
received (but not automatically in a sequence of one-way sends for example).

@subsection wsse_8_4 Signature Validation

To automatically verify the signature of an inbound message signed with DSA or
RSA algorithms, assuming the message contains the X509 certificate as a binary
security token, use:

@code
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);
    soap->cafile = "cacerts.pem";  // file with CA certs of peers
    soap->capath = "dir/to/certs"; // and/or point to CA certs
    soap->crlfile = "revoked.pem"; // use CRL (optional)

    // server:
    if (soap_serve(soap))
      ... // an error occurred

    // client:
    if (soap_call_ns__myMethod(soap, ...))
      ... // an error occurred
@endcode

All locally referenced and signed elements in the signed message will be
verified with @ref soap_wsse_verify_auto using the default settings set with
SOAP_SMD_NONE. Elements that are not signed cannot be verified. Also elements
referenced with absolute URIs that are not part of the message are not
automatically verified. The received message is stored in a DOM accessible with
soap->dom. This enables further analysis of the message content.

For a post-parsing check to verify if an XML element was signed in an inbound
message, use:
@code
    soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);
    ... // client call
    if (soap_wsse_verify_element(soap, "namespaceURI", "tag") > 0)
      ... // at least one element with matching tag and namespace is signed
@endcode
The signed element nesting rules are obeyed, so if the matching element is a
descendent of a signed element, it is signed as well.

Because it is a post check, a client should invoke @ref soap_wsse_verify_element
after the call completed. A service should invoke this function within the
service operation routine, i.e. when the message request is accepted and about
to be processed.

For example, to check whether the wsu:Timestamp element was signed (assuming it is present and message expiration checked with @ref soap_wsse_verify_Timestamp), use @ref soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp").

To check the SOAP Body (either using SOAP 1.1 or 1.2), simply use @ref
soap_wsse_verify_body.

The @ref soap_wsse_verify_auto function keeps processing signed (and unsigned)
messages as they arrive. For unsigned messages this can be expensive and the
verification engine should be shut down using @ref soap_wsse_verify_done.

There can be two problems with signature verification. First, some
WS-Security implementations include SignedInfo/Reference/@URI without targeting
an element, which will produce an error that a Reference URI target does not
exist. Second, certificates provided by the peer are not verifiable unless the
signing CA certificate is included in the cafile or capath. To disable
certificate verification set the fsslverify callback:

@code
    static int ssl_verify(int ok, X509_STORE_CTX *store)
    { // put certificate verification here, return 0 when fails 1 when ok
      return 1;
    }
    ...
    soap_wsse_verify_auto(soap, SOAP_SMD_NONE | SOAP_WSSE_IGNORE_EXTRA_REFS, NULL, 0);
    soap->fsslverify = ssl_verify;
@endcode

To verify the HMAC signature of an inbound message, the HMAC key must be
supplied:

@code
    static char hmac_key[16] = // the same secret key that was used to sign
    { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    soap_wsse_verify_auto(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));

    // server:
    if (soap_serve(soap))
      ... // an error occurred

    // client:
    if (soap_call_ns__myMethod(soap, ...))
      ... // an error occurred
@endcode

To summarize the signature verification process:
-# Register the wsse plugin.
-# For HMAC, obtain the HMAC secret key
-# Use @ref soap_wsse_verify_auto to verify inbound messages.
-# Set the cafile (or capath) to verify certificates of the peers and crlfile
   (optional)
-# After receiving a message, the DOM in soap->dom can be traversed for further    analysis.
-# Always check the function return values for errors. You don't want to accept
   a request or response message with an invalid Security header.
-# Use @ref soap_wsse_verify_done to terminate verification, e.g. to consume
   plain messages more efficiently.

@section wsse_9 Encryption

The material in this section relates to the WS-Security specification section 9.

The wsse plugin must be registered:

@code
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
@endcode

Other flags to consider:

- SOAP_IO_CHUNK for HTTP chunked content to stream messages.
- SOAP_ENC_GZIP for HTTP compression (also enables HTTP chunking).

@subsection wsse_9_1 Encrypting Messages

Encryption should be used in combination with signing. A signature ensures
message integrity while encryption ensures confidentially. Encrypted messages
can be tampered with unless integrity is ensured. Therefore, Section
@ref wsse_8 should be followed to sign and verify message content.

Messages are encrypted using either public key cryptography or a symmetric
secret key. A symmetric secret key should only be shared between the sender and
receiver (or any trusted communicating peer).

Encryption with public key cryptography uses an "envelope" process, where the
public key of the recipient is used to encrypt a temporary (ephemeral) secret
key that is sent together with the secret key-encrypted message to the
recipient. The recipient decrypts the ephemeral key and uses it to decrypt the
message. The public key is usually part of a X509 certificate. The public key
(containing the subject information) is added to the WS-Security header and
used for encryption of the SOAP Body as follows:

@code
    X509 *cert = ...; //
    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL))
      soap_print_fault(soap, stderr);
@endcode

SOAP_MEC_ENV_ENC_DES_CBC specifies envelope encoding with triple DES CBC and
PKCS1 RSA-1_5. Use SOAP_MEC_ENV_ENC_AES256_CBC for AES256 with RSA-OAEP. The
"Cert" parameter is a unique URI to reference the key from the encrypted SOAP
Body.  The above enables the encryption engine for the next message to be sent,
either at the client or server side. The server should use this withing a
server operation (before returning) to enable the service operation response to
be encrypted.

To include a subject key ID in the WS-Security header instead of the entire
public key, specify the subject key ID parameter:

@code
    X509 *cert = ...; //
    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, "Subject Key ID", NULL, NULL))
      soap_print_fault(soap, stderr);
@endcode

The difference with the previous example where no subject key ID was specified
is that the WS-Security header only contains the subject key ID and no longer
the public key in base64 format.

To exclude the encrypted key certificate from the message and include a X509Data element with
IssuerName and SerialNumber:

@code
    X509 *cert = ...;
    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, "CN=Root Agency", "-79441640260855276448009124614332182350"))
      soap_print_fault(soap, stderr);
@endcode

The issuer name and serial number (must be in decimal for
soap_wsse_add_EncryptedKey) of a certificate can be obtained as follows:

@code
    X509 *cert = ...;
    BIGNUM *bn = BN_new();
    char issuer[256], *serial;
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), bn);
    serial = BN_bn2dec(bn);
    OPENSSL_free(bn);
    ...
    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, issuer+1, serial))
      soap_print_fault(soap, stderr);
    ...
    OPENSSL_free(serial);
@code

Note that in the above code the leading slash in "/CN=Root Agency" is excluded from the issuer name.

When excluding the encrypted key certificate from the message, the token
handler callback must be provided on the receiving end to obtain the
certificate that corresponds to the issuer name and serial number. For example:

@code
    soap_register_plugin_arg(soap, soap_wsse, security_token_handler);

    static const void *token_handler(struct soap *soap, int alg, const char *keyname, int *keylen)
    { struct ds__X509IssuerSerialType *issuer;
      switch (alg)
      { case SOAP_SMD_VRFY_DSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA256:
        case SOAP_SMD_VRFY_RSA_SHA512:
          issuer = soap_wsse_get_KeyInfo_SecurityTokenReferenceX509Data(soap);
          if (issuer)
          {
            if (!strcmp(issuer->X509IssuerName, clt_issuer)
             && !strcmp(issuer->X509SerialNumber, clt_serial))
              return (const void*)clt_cert;
            if (!strcmp(issuer->X509IssuerName, srv_issuer)
             && !strcmp(issuer->X509SerialNumber, srv_serial))
              return (const void*)srv_cert;
          }
          break;
        ...
@endcode

To encrypt specific elements of the SOAP Body rather than the entire SOAP Body,
use @ref soap_wsse_add_EncryptedKey_encrypt_only in combination with
@ref soap_wsse_set_wsu_id as follows:

@code
    X509 *cert = ...;
    // the SOAP Body contains one <ns:myContract> and one <ns:myPIN> (not nested)
    soap_wsse_set_wsu_id(soap, "ns:myContract ns:myPIN");
    if (soap_wsse_add_EncryptedKey_encrypt_only(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL, "ns:myContract ns:myPIN"))
      soap_print_fault(soap, stderr);
@endcode

To encrypt the SOAP Body and SOAP Header element(s), such as ds:Signature, use
"SOAP-ENV:Body" with @ref soap_wsse_add_EncryptedKey_encrypt_only:

@code
    X509 *cert = ...;
    soap_wsse_set_wsu_id(soap, "ds:Signature");
    if (soap_wsse_add_EncryptedKey_encrypt_only(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL, "ds:Signature SOAP-ENV:Body"))
      soap_print_fault(soap, stderr);
@endcode

WARNING:
- The @ref soap_wsse_set_wsu_id MUST be used to specify all element tag names
  to encrypt. Additional elements MAY be specified in @ref soap_wsse_set_wsu_id
  (for example elements to digitally sign).
- The elements to encrypt MUST occur EXACTLY ONCE in the SOAP Body.

For symmetric encryption with a shared secret key, generate a 160-bit triple
DES key and make sure both the sender and reciever can use the key without it
being shared by any other party (key exchange problem). Then use the
@ref soap_wsse_encrypt_body function to encrypt the SOAP Body as follows:

@code
    char des_key[20] = ...; // 20-byte (160-bit) DES shared secret key
    if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_DES_CBC, des_key, sizeof(des_key)))
      soap_print_fault(soap, stderr);
@endcode

Triple DES can be selected as above, but also AES128, AES256, or AES512, for
example:

@code
    char aes256_key[32] = ...; // 32-byte (256-bit) AES256 shared secret key
    if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_AES256_CBC, aes256_key, sizeof(aes256_key)))
      soap_print_fault(soap, stderr);
@endcode

To symmetrically encrypt specific elements of the SOAP Body rather than the
entire SOAP Body, use @ref soap_wsse_encrypt_only in combination with
@ref soap_wsse_set_wsu_id as follows:

@code
    char des_key[20] = ...; // 20-byte (160-bit) secret key
    // the SOAP Body contains one <ns:myContract> and one <ns:myPIN> (not nested)
    soap_wsse_set_wsu_id(soap, "ns:myContract ns:myPIN");
    if (soap_wsse_encrypt_only(soap, SOAP_MEC_ENC_DES_CBC, des_key, sizeof(des_key), "ns:myContract ns:myPIN"))
      soap_print_fault(soap, stderr);
@endcode

WARNING:
- The @ref soap_wsse_set_wsu_id MUST be used to specify all element tag names
  to encrypt. Additional elements MAY be specified in @ref soap_wsse_set_wsu_id
  (for example elements to digitally sign).
- The elements to encrypt MUST occur EXACTLY ONCE in the SOAP Body.

@subsection wsse_9_2 Decrypting Message Parts

The wsse engine automatically decrypts message parts, but requires a private
key or secret shared key to do so. A default key can be given to enable
decryption, but it will fail if a non-compatible key was used for encryption.
In that case a token handler callback should be defined by the user to select a
proper decryption key based on the available subject key name or identifier
embedded in the encrypted message.

Here is an example of a token handler callback:

@code
    soap_register_plugin_arg(soap, soap_wsse, security_token_handler);

    const void *security_token_handler(struct soap *soap, int alg, const char *keyname, int *keylen)
    { // Note: 'keyname' argument may be used with shared secret key
      // decryption where the keyname is from the ds:KeyInfo/KeyName content
      if (keyname)
      { ... lookup keyname ...
	const void *key = ...;
	keylen = ...;
        *alg = ...;
	return key;
      }
      // Get the user name from UsernameToken in message
      const char *uid = soap_wsse_get_Username(soap);
      switch (*alg)
      { case SOAP_SMD_VRFY_DSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA1:
        case SOAP_SMD_VRFY_RSA_SHA256:
        case SOAP_SMD_VRFY_RSA_SHA512:
          if (uid)
          { // Lookup uid to retrieve the X509 certificate to verify the signature
            const X509 *cert = ...; 
            return (const void*)cert;
          }
          return NULL; // no certificate: fail
        case SOAP_SMD_HMAC_SHA1:
          if (uid)
          { // Lookup uid to retrieve the HMAC key to verify the signature
            const void *key = ...; 
	    *alg = ...;
	    *keylen = ...;
            return key;
          }
          return NULL; // no certificate: fail
        case SOAP_MEC_ENV_DEC_DES_CBC:
        case SOAP_MEC_ENV_DEC_AES128_CBC:
        case SOAP_MEC_ENV_DEC_AES256_CBC:
        case SOAP_MEC_ENV_DEC_AES256_CBC:
	  // return decryption private key associated with keyname
        case SOAP_MEC_DEC_DES_CBC:
        case SOAP_MEC_DEC_AES128_CBC:
        case SOAP_MEC_DEC_AES256_CBC:
        case SOAP_MEC_DEC_AES512_CBC:
	  // *keylen = ...
	  // return decryption shared secret key associated with keyname
      }
      return NULL; // fail
    }
@endcode

The last two arms are used to return a private key associated with the keyname
paramater, which is a string that contains the subject key id from the public
key information in an encrypted message or the subject key ID string that was
set with @ref soap_wsse_add_EncryptedKey at the sender side.

To set the default private key for envelope decryption, use:

@code
    EVP_PKEY *rsa_private_key = ...;
    soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_private_key, 0);
@endcode

Or to set the default shared secret key for symmetric decryption, use:

@code
    char des_key[20] = ...; // 20-byte (160-bit) triple DES key
    soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_DES_CBC, des_key, sizeof(des_key));
@endcode

The above assumes that triple DES is used, but you can select AES128, AES256,
or AES512:

@code
    char aes256_key[32] = ...; // 32-byte (256-bit) AES256 key
    soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_AES256_CBC, aes256_key, sizeof(aes256_key));
@endcode

If a default key is not set, the token handler callback should be used as
discussed above in this section. Do NOT set a default key if a token handler is
used to handle multiple different keys. The default key mechanism is simpler to
use when only one decryption key is used to decrypt all encrypted messages.

To remove the default key, use:

@code
    soap_wsse_decrypt_auto(soap, SOAP_MEC_NONE, NULL, 0);
@endcode

@subsection wsse_9_3 Example Combining Signing with Encryption/Decryption

Here is an client-side example to use signatures and encryption for the
outbound service request message and verification and decryption of the inbound
response message:

@code
    FILE *fd;
    EVP_PKEY *rsa_private_key;
    X509 *cert;
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);
    fd = fopen("privkey.pem", "r");
    rsa_private_key = PEM_read_PrivateKey(fd, NULL, NULL, "password");
    fclose(fd);
    soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_private_key, 0);
    fd = fopen("cert.pem", "r");
    X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
     || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
     || soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL)
     || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0)
      ... // an error occurred
    else if (soap_call_ns__myMethod(soap, ...))
      ... // a transmission error occurred
    ...
    EVP_PKEY_free(rsa_private_key);
    X509_free(cert);
@endcode

The server-side service operation is as follows:

@code
    FILE *fd;
    EVP_PKEY *rsa_private_key;
    X509 *cert;
    struct soap *soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);
    fd = fopen("privkey.pem", "r");
    rsa_private_key = PEM_read_PrivateKey(fd, NULL, NULL, "password");
    fclose(fd);
    soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_private_key, 0);
    fd = fopen("cert.pem", "r");
    X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    ...
    if (soap_serve(soap))
    { soap_wsse_delete_Security(soap);
      soap_print_fault(soap, stderr);
    }
    ...
    EVP_PKEY_free(rsa_private_key);
    X509_free(cert);
@endcode

where an example service operation could be:

@code
    int ns__myMethod(struct soap *soap, ...)
    { ...
      soap_wsse_delete_Security(soap);
      if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
       || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
       || soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL)
       || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_private_key, 0)
        return soap->error;
      return SOAP_OK;
    }
@endcode

The service operation signs the message using a private key and encrypts the
response message using a public key (from the certificate).

@section wsse_10 Security Timestamps

The material in this section relates to the WS-Security specification section
10.

To add a timestamp with the creation time to the Security header, use:

@code
    soap_wsse_add_Timestamp(soap, NULL, 0); // no expiration
@endcode

The lifetime of a message (in seconds) is passed as the third argument, which
will be displayed as the timestamp expiration time:

@code
    soap_wsse_add_Timestamp(soap, NULL, 10); // 10 seconds lifetime
@endcode

Timestamps, like other header elements, are not automatically secured with a
digital signature. To secure a timestamp, we add an identifier (wsu:Id) to each
element we want the WS-Security plugin to sign thereby making it impossible for
someone to tamper with that part of the message. To do this for the timestamp,
we simply pass a unique identification string as the second argument:

@code
    soap_wsse_add_Timestamp(soap, "Time", 10); // timestamp will be signed
@endcode

@section wsse_11 WS-Security and HTTPS

HTTPS is used at the client side with the usual "https:" URL addressing, shown
here with the registration of the wsse plugin and setting up locks for
thread-safe use of SSL for HTTPS:

@code
    #include "wsseapi.h"
    #include "threads.h"
    struct soap *soap;
    if (CRYPTO_thread_setup())
      ... // error
    soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    if (soap_ssl_client_context(&soap,
      SOAP_SSL_DEFAULT, // requires server authentication
      NULL,             // keyfile for client authentication to server
      NULL,             // the keyfile password
      "cacerts.pem",    // cafile CA certificates to authenticate the server
      NULL,             // capath CA directory path to certificates
      NULL
    ))
      ... // error
    soap->cafile = "cacerts.pem";  // same as above (or overrides the above)
    soap->capath = "dir/to/certs"; // and/or point to CA certs
    soap->crlfile = "revoked.pem"; // use CRL (optional)
    ... // set up WS-Security for signatures/encryption etc
    if (soap_call_ns__myMethod(soap, "https://...", ...))
      ... // error
    ... // process response results
    soap_destroy(soap);
    soap_end(soap);
    soap_free(soap);
    CRYPTO_thread_cleanup();
@endcode

The CRYPTO threads should be set up before any threads are created.

The soap_ssl_client_context only needs to be set up once. Use the following
flags:

- SOAP_SSL_DEFAULT requires server authentication, CA certs should be used
- SOAP_SSL_NO_AUTHENTICATION disables server authentication
- SOAP_SSL_SKIP_HOST_CHECK disables server authentication host check

The server uses the following:

@code
    #include "wsseapi.h"
    #include "threads.h"
    SOAP_SOCKET m, s;
    int port = 443;
    struct soap *soap;
    if (CRYPTO_thread_setup())
      ... // error
    soap = soap_new1(SOAP_XML_CANONICAL | SOAP_XML_INDENT);
    soap_register_plugin(soap, soap_wsse);
    if (soap_ssl_server_context(&soap,
      SOAP_SSL_DEFAULT, // requires server to authenticate, but not the client
      server.pem,       // keyfile for authentication to client
      "password",       // the keyfile password
      NULL,             // CA certificates to authenticate the client
      NULL,             // CA directory path to certificates
      NULL,             // use RSA 2048 bits (or give file name with DH param)
      NULL,
      NULL
    ))
      ... // error
    if (!soap_valid_socket(m = soap_bind(soap, NULL, port, 100))
      ... // error
    for (;;)
    { if (!soap_valid_socket(s = soap_accept(soap)))
        ... // error
      THREAD_CREATE(&tid, (void*(*)(void*))&process_request, soap_copy(soap));
    }
    soap_destroy(soap);
    soap_end(soap);
    soap_free(soap);
    CRYPTO_thread_cleanup();
@endcode

where we define a process_request function that is executed by the thread to
process the request (on a copy of the soap context struct):

@code
  void *process_request(struct soap *soap)
  { ... // set up WS-Security for signatures/encryption etc
    if (soap_ssl_accept(soap)
     || soap_serve(soap))
      ... // error
    soap_destroy(soap);
    soap_end(soap);
    soap_free(soap);
  }
@endcode

The soap_ssl_server_context only needs to be set up once. Use the following
flags:

- SOAP_SSL_DEFAULT requires server authentication, but no client authentication
- SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION requires client authentication

We need to define the thread set up and clean up operations as follows:

@code
  struct CRYPTO_dynlock_value
  { MUTEX_TYPE mutex;
  };

  static MUTEX_TYPE *mutex_buf;

  static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
  { struct CRYPTO_dynlock_value *value;
    value = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value));
    if (value)
      MUTEX_SETUP(value->mutex);
    return value;
  }

  static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
  { if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(l->mutex);
    else
      MUTEX_UNLOCK(l->mutex);
  }

  static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
  { MUTEX_CLEANUP(l->mutex);
    free(l);
  }

  void locking_function(int mode, int n, const char *file, int line)
  { if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(mutex_buf[n]);
    else
      MUTEX_UNLOCK(mutex_buf[n]);
  }

  unsigned long id_function()
  { return (unsigned long)THREAD_ID;
  }

  int CRYPTO_thread_setup()
  { int i;
    mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!mutex_buf)
      return SOAP_EOM;
    for (i = 0; i < CRYPTO_num_locks(); i++)
      MUTEX_SETUP(mutex_buf[i]);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
    return SOAP_OK;
  }

  void CRYPTO_thread_cleanup()
  { int i;
    if (!mutex_buf)
      return;
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
      MUTEX_CLEANUP(mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
  }
@endcode

For additional details and examples, see the user guide and examples in the
gSOAP package directory gsoap/samples/ssl.

@section wsse_12 Miscellaneous

The Security header block was generated from the WS-Security schema with the
wsdl2h tool and WS/WS-typemap.dat:

@code
    > wsdl2h -cegxy -o wsse.h -t WS/WS-typemap.dat WS/wsse.xsd
@endcode

The same process was used to generate the header file ds.h from the XML digital
signatures core schema, and the xenc.h encryption schema:

@code
    > wsdl2h -cuxy -o ds.h -t WS/WS-typemap.dat WS/ds.xsd
    > wsdl2h -cuxy -o xenc.h -t WS/WS-typemap.dat WS/xenc.xsd
@endcode

The import/wsse.h file has the following definition for the Security header
block:

@code
typedef struct _wsse__Security
{       struct _wsu__Timestamp*                 wsu__Timestamp;
        struct _wsse__UsernameToken*            UsernameToken;
        struct _wsse__BinarySecurityToken*      BinarySecurityToken;
        struct xenc__EncryptedKeyType*          xenc__EncryptedKey;
        struct _xenc__ReferenceList*            xenc__ReferenceList;
        struct ds__SignatureType*               ds__Signature;
        @char*                                  SOAP_ENV__actor;
        @char*                                  SOAP_ENV__role;
} _wsse__Security;
@endcode

The _wsse__Security header is modified by a WS/WS-typemap.dat mapping rule to
include additional details.

@section wsse_13 Encryption Limitations

- Individual encryption/decryption of simple content (CDATA content) with @ref
  soap_wsse_add_EncryptedKey_encrypt_only IS NOT SUPPORTED. Encrypt the entire
  SOAP Body or encrypt elements with complex content (complexType and
  complexContent elements that have sub elements).

- Encryption is performed after signing (likewise, signatures are verified
  after decryption). Signing after encryption is not supported.

@section wsse_wsc WS-SecureConversation

To use a WS-SecureConversation security context token (SCT) with WS-Security:

@code
const char *identifier = "...";
soap_wsse_add_SecurityContextToken(soap, "SCT", identifier);
@endcode

In this example a context has been established and the secret that is
identified by the 'identifier' string is known to both parties. This secret is
used to sign the message body. The "SCT" is a wsu:Id, which is used as a
reference to sign the token.

*/

#include "wsseapi.h"
#include "smdevp.h"
#include "mecevp.h"
#include "threads.h"	/* only need threads to enable mutex for MT */

#if defined(SOAP_WSA_2003) || defined(SOAP_WSA_2004) || defined(SOAP_WSA_200408) || defined(SOAP_WSA_2005)
#include "wsaapi.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Plugin identification for plugin registry */
const char soap_wsse_id[14] = SOAP_WSSE_ID;

/** Maximum number of SignedInfo References */
#define SOAP_WSSE_MAX_REF	(100)

/** Clock skew between machines (in sec) to fit message expiration in window */
#define SOAP_WSSE_CLKSKEW	(300)

/** Size of the random nonce */
#define SOAP_WSSE_NONCELEN	(20)
/** Digest authentication accepts messages that are not older than creation time + SOAP_WSSE_NONCETIME */
#define SOAP_WSSE_NONCETIME	(SOAP_WSSE_CLKSKEW + 240)

/******************************************************************************\
 *
 * Common URIs
 *
\******************************************************************************/

const char *wsse_PasswordTextURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const char *wsse_PasswordDigestURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const char *wsse_Base64BinaryURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
const char *wsse_X509v3URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
const char *wsse_X509v3SubjectKeyIdentifierURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier";

const char *ds_sha1URI = "http://www.w3.org/2000/09/xmldsig#sha1";
const char *ds_sha256URI = "http://www.w3.org/2001/04/xmlenc#sha256";
const char *ds_sha512URI = "http://www.w3.org/2001/04/xmlenc#sha512";

const char *ds_hmac_sha1URI = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
const char *ds_hmac_sha256URI = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
const char *ds_hmac_sha512URI = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";

const char *ds_dsa_sha1URI = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

const char *ds_rsa_sha1URI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const char *ds_rsa_sha256URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const char *ds_rsa_sha512URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

const char *xenc_rsa15URI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const char *xenc_rsaesURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const char *xenc_3desURI = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
const char *xenc_aes128URI = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const char *xenc_aes192URI = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const char *xenc_aes256URI = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const char *xenc_aes512URI = "http://www.w3.org/2001/04/xmlenc#aes512-cbc";
const char *xenc_elementURI = "http://www.w3.org/2001/04/xmlenc#Element";
const char *xenc_contentURI = "http://www.w3.org/2001/04/xmlenc#Content";

const char *ds_URI = "http://www.w3.org/2000/09/xmldsig#";
const char *c14n_URI = "http://www.w3.org/2001/10/xml-exc-c14n#";
const char *wsu_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/******************************************************************************\
 *
 * Digest authentication session
 *
\******************************************************************************/

/**
@struct soap_wsse_session
@brief Digest authentication session data
*/
struct soap_wsse_session
{ struct soap_wsse_session *next;	/**< Next session in list */
  time_t expired;			/**< Session expiration */
  char hash[SOAP_SMD_SHA1_SIZE];	/**< SHA1 digest */
  char nonce[1]; /**< Nonce string flows into region below this struct */
};

/** The digest authentication session database */
static struct soap_wsse_session *soap_wsse_session = NULL;

/** Lock for digest authentication session database exclusive access */
static MUTEX_TYPE soap_wsse_session_lock = MUTEX_INITIALIZER;

static char* soap_wsse_ids(struct soap *soap, const char *tags);

static int soap_wsse_session_verify(struct soap *soap, const char hash[SOAP_SMD_SHA1_SIZE], const char *created, const char *nonce);
static void soap_wsse_session_cleanup(struct soap *soap);
static void calc_digest(struct soap *soap, const char *created, const char *nonce, int noncelen, const char *password, char hash[SOAP_SMD_SHA1_SIZE]);
static void calc_nonce(struct soap *soap, char nonce[SOAP_WSSE_NONCELEN]);

static int soap_wsse_init(struct soap *soap, struct soap_wsse_data *data, const void *(*arg)(struct soap*, int*, const char*, int*));
static int soap_wsse_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src);
static void soap_wsse_delete(struct soap *soap, struct soap_plugin *p);

static int soap_wsse_preparesend(struct soap *soap, const char *buf, size_t len);
static int soap_wsse_preparefinalsend(struct soap *soap);
static void soap_wsse_preparecleanup(struct soap *soap, struct soap_wsse_data *data);
static int soap_wsse_preparefinalrecv(struct soap *soap);

static int soap_wsse_header(struct soap *soap);
static int soap_wsse_element_begin_in(struct soap *soap, const char *tag);
static int soap_wsse_element_end_in(struct soap *soap, const char *tag1, const char *tag2);
static int soap_wsse_element_begin_out(struct soap *soap, const char *tag);
static int soap_wsse_element_end_out(struct soap *soap, const char *tag);

static size_t soap_wsse_verify_nested(struct soap *soap, struct soap_dom_element *dom, const char *URI, const char *tag);

/******************************************************************************\
 *
 * wsse:Security header element
 *
\******************************************************************************/

/**
@fn _wsse__Security* soap_wsse_add_Security(struct soap *soap)
@brief Adds Security header element.
@param soap context
@return _wsse__Security object
*/
struct _wsse__Security*
soap_wsse_add_Security(struct soap *soap)
{ DBGFUN("soap_wsse_add_Security");
  /* if we don't have a SOAP Header, create one */
  soap_header(soap);
  /* if we don't have a wsse:Security element in the SOAP Header, create one */
  if (!soap->header->wsse__Security)
  { soap->header->wsse__Security = (_wsse__Security*)soap_malloc(soap, sizeof(_wsse__Security));
    if (!soap->header->wsse__Security)
      return NULL;
    soap_default__wsse__Security(soap, soap->header->wsse__Security);
  }
  return soap->header->wsse__Security;
}

/**
@fn _wsse__Security* soap_wsse_add_Security_actor(struct soap *soap, const char *actor)
@brief Adds Security header element with actor or role attribute.
@param soap context
@param actor string
@return _wsse__Security object
*/
struct _wsse__Security*
soap_wsse_add_Security_actor(struct soap *soap, const char *actor)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  DBGFUN1("soap_wsse_add_Security_actor", "actor=%s", actor);
  if (soap->namespaces && !strcmp(soap->namespaces[0].ns, "http://schemas.xmlsoap.org/soap/envelope/"))
    security->SOAP_ENV__actor = soap_strdup(soap, actor);
  else
    security->SOAP_ENV__role = soap_strdup(soap, actor);
  return security;
}

/**
@fn void soap_wsse_delete_Security(struct soap *soap)
@brief Deletes Security header element.
@param soap context
*/
void
soap_wsse_delete_Security(struct soap *soap)
{ DBGFUN("soap_wsse_delete_Security");
  if (soap->header)
    soap->header->wsse__Security = NULL;
}

/**
@fn _wsse__Security* soap_wsse_Security(struct soap *soap)
@brief Returns Security header element if present.
@param soap context
@return _wsse__Security object or NULL
*/
struct _wsse__Security*
soap_wsse_Security(struct soap *soap)
{ if (soap->header)
    return soap->header->wsse__Security;
  return NULL;
}

/******************************************************************************\
 *
 * wsse:Security/ds:Signature header element
 *
\******************************************************************************/

/**
@fn ds__SignatureType* soap_wsse_add_Signature(struct soap *soap)
@brief Adds Signature header element.
@param soap context
@return ds__SignatureType object
*/
struct ds__SignatureType*
soap_wsse_add_Signature(struct soap *soap)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  DBGFUN("soap_wsse_add_Signature");
  /* if we don't have a ds:Signature, create one */
  if (!security->ds__Signature)
  { security->ds__Signature = (ds__SignatureType*)soap_malloc(soap, sizeof(ds__SignatureType));
    if (!security->ds__Signature)
      return NULL;
    soap_default_ds__SignatureType(soap, security->ds__Signature); 
  }
  return security->ds__Signature;
}

/**
@fn void soap_wsse_delete_Signature(struct soap *soap)
@brief Deletes Signature header element.
@param soap context
*/
void
soap_wsse_delete_Signature(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  DBGFUN("soap_wsse_delete_Signature");
  if (security)
    security->ds__Signature = NULL;
}

/**
@fn ds__SignatureType* soap_wsse_Signature(struct soap *soap)
@brief Returns Signature header element if present.
@param soap context
@return ds__SignatureType object or NULL
*/
struct ds__SignatureType*
soap_wsse_Signature(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  if (security)
    return security->ds__Signature;
  return NULL;
}

/******************************************************************************\
 *
 * wsse:Security/wsu:Timestamp header element
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_Timestamp(struct soap *soap, const char *id, time_t lifetime)
@brief Adds Timestamp element with optional expiration date+time (lifetime).
@param[in] soap context
@param[in] id for signature referencing or NULL
@param[in] lifetime expressed in time_t units, or 0 for no expiration
@return SOAP_OK
*/
int
soap_wsse_add_Timestamp(struct soap *soap, const char *id, time_t lifetime)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  time_t now = time(NULL);
  char *created = soap_strdup(soap, soap_dateTime2s(soap, now));
  char *expired = lifetime ? soap_strdup(soap, soap_dateTime2s(soap, now + lifetime)) : NULL;
  DBGFUN1("soap_wsse_add_Timestamp", "id=%s", id?id:"");
  /* allocate a Timestamp if we don't have one already */
  if (!security->wsu__Timestamp)
  { security->wsu__Timestamp = (_wsu__Timestamp*)soap_malloc(soap, sizeof(_wsu__Timestamp));
    if (!security->wsu__Timestamp)
      return soap->error = SOAP_EOM;
  }
  soap_default__wsu__Timestamp(soap, security->wsu__Timestamp);
  /* populate the wsu:Timestamp element */
  security->wsu__Timestamp->wsu__Id = soap_strdup(soap, id);
  security->wsu__Timestamp->Created = created;
  security->wsu__Timestamp->Expires = expired;
  return SOAP_OK;
}

/**
@fn _wsu__Timestamp *soap_wsse_Timestamp(struct soap *soap)
@brief Returns Timestamp element if present.
@param soap context
@return _wsu__Timestamp object or NULL
*/
struct _wsu__Timestamp*
soap_wsse_Timestamp(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  if (security)
    return security->wsu__Timestamp;
  return NULL;
}

/**
@fn int soap_wsse_verify_Timestamp(struct soap *soap)
@brief Verifies the Timestamp/Expires element against the current time.
@param soap context
@return SOAP_OK or SOAP_FAULT with wsse:FailedAuthentication fault

Sets wsse:FailedAuthentication fault if wsu:Timestamp is expired. The
SOAP_WSSE_CLKSKEW value is used as a margin to mitigate clock skew. Keeps
silent when no timestamp is supplied or no expiration date is included in the
wsu:Timestamp element.
*/
int
soap_wsse_verify_Timestamp(struct soap *soap)
{ _wsu__Timestamp *timestamp = soap_wsse_Timestamp(soap);
  DBGFUN("soap_wsse_verify_Timestamp");
  /* if we have a timestamp with an expiration date, check it */
  if (timestamp && timestamp->Expires)
  { time_t now = time(NULL), expired;
    soap_s2dateTime(soap, timestamp->Expires, &expired);
    if (expired + SOAP_WSSE_CLKSKEW <= now)
    { const char *code = soap_wsu__tTimestampFault2s(soap, wsu__MessageExpired);
      return soap_wsse_sender_fault_subcode(soap, code, "Message has expired", timestamp->Expires);
    }
  }
  return SOAP_OK;
}

/******************************************************************************\
 *
 * wsse:Security/UsernameToken header element
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_UsernameTokenText(struct soap *soap, const char *id, const char *username, const char *password)
@brief Adds UsernameToken element with optional clear-text password.
@param soap context
@param[in] id string for signature referencing or NULL
@param[in] username string
@param[in] password string or NULL to omit the password
@return SOAP_OK

Passwords are sent in the clear, so transport-level encryption is required.
Note: this release supports the use of at most one UsernameToken in the header.
*/
int
soap_wsse_add_UsernameTokenText(struct soap *soap, const char *id, const char *username, const char *password)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  DBGFUN2("soap_wsse_add_UsernameTokenText", "id=%s", id?id:"", "username=%s", username?username:"");
  /* allocate a UsernameToken if we don't have one already */
  if (!security->UsernameToken)
  { if (!(security->UsernameToken = (_wsse__UsernameToken*)soap_malloc(soap, sizeof(_wsse__UsernameToken))))
      return soap->error = SOAP_EOM;
  }
  soap_default__wsse__UsernameToken(soap, security->UsernameToken);
  /* populate the UsernameToken */
  security->UsernameToken->wsu__Id = soap_strdup(soap, id);
  security->UsernameToken->Username = soap_strdup(soap, username);
  /* allocate and populate the Password */
  if (password)
  { if (!(security->UsernameToken->Password = (_wsse__Password*)soap_malloc(soap, sizeof(_wsse__Password))))
      return soap->error = SOAP_EOM;
    soap_default__wsse__Password(soap, security->UsernameToken->Password);
    security->UsernameToken->Password->Type = (char*)wsse_PasswordTextURI;
    security->UsernameToken->Password->__item = soap_strdup(soap, password);
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_add_UsernameTokenDigest(struct soap *soap, const char *id, const char *username, const char *password)
@brief Adds UsernameToken element for digest authentication.
@param soap context
@param[in] id string for signature referencing or NULL
@param[in] username string
@param[in] password string
@return SOAP_OK

Computes SHA1 digest of the time stamp, a nonce, and the password. The digest
provides the authentication credentials. Passwords are NOT sent in the clear.
Note: this release supports the use of at most one UsernameToken in the header.
*/
int
soap_wsse_add_UsernameTokenDigest(struct soap *soap, const char *id, const char *username, const char *password)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  time_t now = time(NULL);
  const char *created = soap_dateTime2s(soap, now);
  char HA[SOAP_SMD_SHA1_SIZE], HABase64[29];
  char nonce[SOAP_WSSE_NONCELEN], *nonceBase64;
  DBGFUN2("soap_wsse_add_UsernameTokenDigest", "id=%s", id?id:"", "username=%s", username?username:"");
  /* generate a nonce */
  calc_nonce(soap, nonce);
  nonceBase64 = soap_s2base64(soap, (unsigned char*)nonce, NULL, SOAP_WSSE_NONCELEN);
  /* The specs are not clear: compute digest over binary nonce or base64 nonce? */
  /* compute SHA1(created, nonce, password) */
  calc_digest(soap, created, nonce, SOAP_WSSE_NONCELEN, password, HA);
  /* Hm...?
  calc_digest(soap, created, nonceBase64, strlen(nonceBase64), password, HA);
  */
  soap_s2base64(soap, (unsigned char*)HA, HABase64, SOAP_SMD_SHA1_SIZE);
  /* populate the UsernameToken with digest */
  soap_wsse_add_UsernameTokenText(soap, id, username, HABase64);
  /* populate the remainder of the password, nonce, and created */
  security->UsernameToken->Password->Type = (char*)wsse_PasswordDigestURI;
  security->UsernameToken->Nonce = nonceBase64;
  security->UsernameToken->wsu__Created = soap_strdup(soap, created);
  return SOAP_OK;
}

/**
@fn _wsse__UsernameToken* soap_wsse_UsernameToken(struct soap *soap, const char *id)
@brief Returns UsernameToken element if present.
@param soap context
@param[in] id string of UsernameToken or NULL
@return _wsse__UsernameToken object or NULL

Note: this release supports the use of at most one UsernameToken in the header.
*/
struct _wsse__UsernameToken*
soap_wsse_UsernameToken(struct soap *soap, const char *id)
{ _wsse__Security *security = soap_wsse_Security(soap);
  if (security
   && security->UsernameToken
   && (!id || (security->UsernameToken->wsu__Id
            && !strcmp(security->UsernameToken->wsu__Id, id))))
    return security->UsernameToken;
  return NULL;
}

/**
@fn const char* soap_wsse_get_Username(struct soap *soap)
@brief Returns UsernameToken/username string or wsse:FailedAuthentication fault.
@param soap context
@return UsernameToken/username string or NULL with wsse:FailedAuthentication fault error set
@see soap_wsse_verify_Password

The returned username should be used to lookup the user's password in a
dictionary or database for server-side authentication with
soap_wsse_verify_Password.
*/
const char*
soap_wsse_get_Username(struct soap *soap)
{ _wsse__UsernameToken *token = soap_wsse_UsernameToken(soap, NULL);
  DBGFUN("soap_wsse_get_Username");
  if (token)
    return token->Username;
  soap_wsse_fault(soap, wsse__FailedAuthentication, "Username authentication required");
  return NULL;
}

/**
@fn int soap_wsse_verify_Password(struct soap *soap, const char *password)
@brief Verifies the supplied password or sets wsse:FailedAuthentication fault.
@param soap context
@param[in] password string to verify against
@return SOAP_OK (authorized) or SOAP_FAULT with wsse:FailedAuthentication fault

The verification supports both clear-text password verification and digest
password authentication. For digest authentication a history mechanism with a
digest authentication session database ensures protection against replay
attacks.
Note: this release supports the use of at most one UsernameToken in the header.
*/
int
soap_wsse_verify_Password(struct soap *soap, const char *password)
{ _wsse__UsernameToken *token = soap_wsse_UsernameToken(soap, NULL);
  DBGFUN("soap_wsse_verify_Password");
  /* if we have a UsernameToken with a Password, check it */
  if (token && token->Password)
  { /* password digest or text? */
    if (token->Password->Type
     && !strcmp(token->Password->Type, wsse_PasswordDigestURI))
    { /* check password digest: compute SHA1(created, nonce, password) */
      if (token->Nonce
       && token->wsu__Created
       && strlen(token->Password->__item) == 28)	/* digest pw len = 28 */
      { char HA1[SOAP_SMD_SHA1_SIZE], HA2[SOAP_SMD_SHA1_SIZE];
        /* The specs are not clear: compute digest over binary nonce or base64 nonce? The formet appears to be the case: */
        int noncelen;
        const char *nonce = soap_base642s(soap, token->Nonce, NULL, 0, &noncelen);
        /* compute HA1 = SHA1(created, nonce, password) */
        calc_digest(soap, token->wsu__Created, nonce, noncelen, password, HA1);
        /*
        calc_digest(soap, token->wsu__Created, token->Nonce, strlen(token->Nonce), password, HA1);
        */
        /* get HA2 = supplied digest from base64 Password */
        soap_base642s(soap, token->Password->__item, HA2, SOAP_SMD_SHA1_SIZE, NULL);
        /* compare HA1 to HA2 */
        if (!memcmp(HA1, HA2, SOAP_SMD_SHA1_SIZE))
        { /* authorize if HA1 and HA2 identical and not replay attack */
          if (!soap_wsse_session_verify(soap, HA1, token->wsu__Created, token->Nonce))
            return SOAP_OK;
          return soap->error; 
        }
      }
    }
    else
    { /* check password text */
      if (!strcmp(token->Password->__item, password))
        return SOAP_OK;
    }
  }
  return soap_wsse_fault(soap, wsse__FailedAuthentication, NULL);
}

/******************************************************************************\
 *
 * wsse:Security/BinarySecurityToken header element
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_BinarySecurityToken(struct soap *soap, const char *id, const char *valueType, const unsigned char *data, int size)
@brief Adds BinarySecurityToken element.
@param soap context
@param[in] id string for signature referencing or NULL
@param[in] valueType string
@param[in] data points to binary token data
@param[in] size is length of binary token
@return SOAP_OK
*/
int
soap_wsse_add_BinarySecurityToken(struct soap *soap, const char *id, const char *valueType, const unsigned char *data, int size)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  DBGFUN2("wsse_add_BinarySecurityToken", "id=%s", id?id:"", "valueType=%s", valueType?valueType:"");
  /* allocate BinarySecurityToken if we don't already have one */
  if (!security->BinarySecurityToken)
  { if (!(security->BinarySecurityToken = (_wsse__BinarySecurityToken*)soap_malloc(soap, sizeof(_wsse__BinarySecurityToken))))
      return soap->error = SOAP_EOM;
  }
  soap_default__wsse__BinarySecurityToken(soap, security->BinarySecurityToken);
  /* populate the BinarySecurityToken */
  security->BinarySecurityToken->wsu__Id = soap_strdup(soap, id);
  security->BinarySecurityToken->ValueType = soap_strdup(soap, valueType);
  security->BinarySecurityToken->EncodingType = (char*)wsse_Base64BinaryURI;
  security->BinarySecurityToken->__item = soap_s2base64(soap, data, NULL, size);
  return SOAP_OK;
}

/**
@fn int soap_wsse_add_BinarySecurityTokenX509(struct soap *soap, const char *id, X509 *cert)
@brief Adds BinarySecurityToken element with X509 certificate.
@param soap context
@param[in] id string for signature reference
@param[in] cert points to the X509 certificate
@return SOAP_OK or SOAP_EOM

This function uses i2d_X509 from the the OpenSSL library to convert an X509
object to binary DER format.
*/
int
soap_wsse_add_BinarySecurityTokenX509(struct soap *soap, const char *id, X509 *cert)
{ int derlen;
  unsigned char *der, *s;
  if (!cert)
    return soap_wsse_fault(soap, wsse__InvalidSecurityToken, "Missing certificate");
  /* determine the storage requirement */
  derlen = i2d_X509(cert, NULL);
  if (derlen < 0)
    return soap_wsse_fault(soap, wsse__InvalidSecurityToken, "Invalid certificate");
  /* use the gSOAP engine's look-aside buffer to temporarily hold the cert */
  if (soap_store_lab(soap, NULL, derlen))
    return SOAP_EOM;
  s = der = (unsigned char*)soap->labbuf;
  /* store in DER format */
  i2d_X509(cert, &s);
  /* populate the BinarySecurityToken with base64 certificate data */
  return soap_wsse_add_BinarySecurityToken(soap, id, wsse_X509v3URI, der, derlen);
}

/**
@fn int soap_wsse_add_BinarySecurityTokenPEM(struct soap *soap, const char *id, const char *filename)
@brief Adds BinarySecurityToken element from a PEM file.
@param soap context
@param[in] id string for signature reference
@param[in] filename
@return SOAP_OK or SOAP_FAULT with wsse__InvalidSecurity fault when file cannot be read or does not contain a valid certificate

This function uses PEM_read_X509 from the the OpenSSL library to read a
certificate from a PEM formatted file.
*/
int
soap_wsse_add_BinarySecurityTokenPEM(struct soap *soap, const char *id, const char *filename)
{ FILE *fd;
  DBGFUN2("soap_wsse_add_BinarySecurityTokenPEM", "id=%s", id?id:"", "filename=%s", filename?filename:"");
  if ((fd = fopen(filename, "r")))
  { /* read the certificate */
    X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    /* if okay, populate the BinarySecurityToken element */
    if (cert)
    { int err = soap_wsse_add_BinarySecurityTokenX509(soap, id, cert);
      X509_free(cert);
      return err;
    }
  }
  return soap_wsse_fault(soap, wsse__InvalidSecurityToken, "Missing certificate");
}

/**
@fn _wsse__BinarySecurityToken* soap_wsse_BinarySecurityToken(struct soap *soap, const char *id)
@brief Returns BinarySecurityToken element if present.
@param soap context
@param[in] id string of token to get or NULL
@return _wsse__BinarySecurityToken object or NULL
*/
struct _wsse__BinarySecurityToken*
soap_wsse_BinarySecurityToken(struct soap *soap, const char *id)
{ _wsse__Security *security = soap_wsse_Security(soap);
  if (security
   && security->BinarySecurityToken
   && (!id || (security->BinarySecurityToken->wsu__Id
            && !strcmp(security->BinarySecurityToken->wsu__Id, id))))
    return security->BinarySecurityToken;
  DBGLOG(TEST, SOAP_MESSAGE(fdebug, "No BinarySecurityToken id=%s, pointer=%p to token found\n", id, security->BinarySecurityToken));
  return NULL;
}

/**
@fn int soap_wsse_get_BinarySecurityToken(struct soap *soap, const char *id, char **valueType, unsigned char **data, int *size)
@brief Get wsse:BinarySecurityToken element token data in binary form.
@param soap context
@param[in] id string of token to get or NULL
@param[out] valueType string
@param[out] data points to binary token data
@param[out] size is length of binary token
@return SOAP_OK or SOAP_FAULT with wsse:SecurityTokenUnavailable fault
*/
int
soap_wsse_get_BinarySecurityToken(struct soap *soap, const char *id, char **valueType, unsigned char **data, int *size)
{ _wsse__BinarySecurityToken *token = soap_wsse_BinarySecurityToken(soap, id);
  DBGFUN1("soap_wsse_get_BinarySecurityToken", "id=%s", id?id:"");
  if (token)
  { *valueType = token->ValueType;
    /* it appears we don't need HexBinary after all
    if (token->EncodingType && !strcmp(token->EncodingType, wsse_HexBinaryURI))
      *data = (unsigned char*)soap_hex2s(soap, token->__item, NULL, 0, size);
    else
    */
    /* assume token is represented in base64 by default */
    *data = (unsigned char*)soap_base642s(soap, token->__item, NULL, 0, size);
    if (*data)
      return SOAP_OK;
  }
  return soap_wsse_fault(soap, wsse__SecurityTokenUnavailable, "BinarySecurityToken required");
}

/**
@fn X509* soap_wsse_get_BinarySecurityTokenX509(struct soap *soap, const char *id)
@brief Get X509 wsse:BinarySecurityToken certificate and verify its content.
@param soap context
@param[in] id string of token to get or NULL
@return X509 certificate (dynamically allocated) or NULL with wsse:SecurityTokenUnavailable fault
*/
X509*
soap_wsse_get_BinarySecurityTokenX509(struct soap *soap, const char *id)
{ X509 *cert = NULL;
  char *valueType = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
  const unsigned char *data;
#else
  unsigned char *data;
#endif
  int size;
  DBGFUN1("soap_wsse_get_BinarySecurityTokenX509", "id=%s", id?id:"");
  if (!soap_wsse_get_BinarySecurityToken(soap, id, &valueType, (unsigned char**)&data, &size)
   && valueType
   && !strcmp(valueType, wsse_X509v3URI))
    cert = d2i_X509(NULL, &data, size);
  /* verify the certificate */
  if (!cert || soap_wsse_verify_X509(soap, cert))
    return NULL;
  return cert;
}

/**
@fn int soap_wsse_verify_X509(struct soap *soap, X509 *cert)
@brief Verifies X509 certificate against soap->cafile, soap->capath, and soap->crlfile
@param soap context
@param[in] cert X509 certificate
@return SOAP_OK or fault

This is an expensive operation. Whenever a new soap context is created, the
cafile and objects are loaded into that context each time we need to verify a
certificate.
*/
int
soap_wsse_verify_X509(struct soap *soap, X509 *cert)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  X509_STORE_CTX *verify;
  DBGFUN("soap_wsse_verify_X509");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_sign", "Plugin not registered", SOAP_PLUGIN_ERROR);
  if (!cert)
    return soap_wsse_sender_fault(soap, "soap_wsse_verify_X509", "No certificate");
  if (!data->store)
  { if (!(data->store = X509_STORE_new()))
      return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not create X509_STORE object");
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Setting up a new X509 store\n"));
    X509_STORE_set_verify_cb_func(data->store, soap->fsslverify);
    if (soap->cafile || soap->capath)
    { if (X509_STORE_load_locations(data->store, soap->cafile, soap->capath) != 1)
        return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not load CA file or path");
    }
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
    if (soap->crlfile)
    { X509_LOOKUP *lookup;
      if (!(lookup = X509_STORE_add_lookup(data->store, X509_LOOKUP_file())))
        return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not create X509_LOOKUP object");
      if (X509_load_crl_file(lookup, soap->crlfile, X509_FILETYPE_PEM) != 1)
        return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not read the CRL file");
      X509_STORE_set_flags(data->store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }
#endif
  }
  if (!(verify = X509_STORE_CTX_new()))
    return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not create X509_STORE_CTX object");
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  if (X509_STORE_CTX_init(verify, data->store, cert, NULL) != 1)
  { X509_STORE_CTX_free(verify);
    return soap_wsse_receiver_fault(soap, "soap_wsse_verify_X509", "Could not initialize X509_STORE_CTX object");
  }
#else
  X509_STORE_CTX_init(verify, data->store, cert, NULL);
#endif
  if (X509_verify_cert(verify) != 1)
  { X509_STORE_CTX_free(verify);
    return soap_wsse_sender_fault(soap, "soap_wsse_verify_X509", "Invalid certificate");
  }
  DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Certificate is valid\n"));
#ifdef SOAP_DEBUG
  { char buf[1024];
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "certificate issuer %s\n", buf));
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "certificate subject %s\n", buf));
  }
#endif
  X509_STORE_CTX_free(verify);
  return SOAP_OK;
}

/******************************************************************************\
 *
 * wsc:SecurityContextToken
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_SecurityContextToken(struct soap *soap, const char *id, const char *identifier)
@brief Adds wsc:SecurityContextToken/Identifier and SecurityTokenReference to it
@param soap context
@param[in] id string for signature reference (required)
@param[in] identifier wsc:Identifier value (required)
@return SOAP_OK or error code
*/
int
soap_wsse_add_SecurityContextToken(struct soap *soap, const char *id, const char *identifier)
{ char *URI;
  _wsse__Security *security = soap_wsse_add_Security(soap);
  DBGFUN2("soap_wsse_add_SecurityContextToken", "id=%s", id, "identifier=%s", identifier?identifier:"");
  /* allocate wsc:SecurityContextToken if we don't already have one */
  if (!security->wsc__SecurityContextToken)
  { if (!(security->wsc__SecurityContextToken = (struct wsc__SecurityContextTokenType*)soap_malloc(soap, sizeof(struct wsc__SecurityContextTokenType))))
      return soap->error = SOAP_EOM;
  }
  soap_default_wsc__SecurityContextTokenType(soap, security->wsc__SecurityContextToken);
  /* populate the wsc:SecurityContextToken */
  if (!(URI = (char*)soap_malloc(soap, strlen(id) + 2)))
    return soap->error = SOAP_EOM;
  *URI = '#';
  security->wsc__SecurityContextToken->wsu__Id = strcpy(URI + 1, id);
  security->wsc__SecurityContextToken->Identifier = soap_strdup(soap, identifier);
  /* set SecurityTokenReference */
  return soap_wsse_add_KeyInfo_SecurityTokenReferenceURI(soap, URI, NULL);
}

/**
@fn const char *soap_wsse_get_SecurityContextToken(struct soap *soap)
@brief Returns wsc:SecurityContextToken/Identifier string value or NULL
@param soap context
@return wsc:SecurityContextToken/Identifier string value value or NULL
*/
const char *
soap_wsse_get_SecurityContextToken(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  DBGFUN("soap_wsse_SecurityContextToken");
  if (security->wsc__SecurityContextToken && security->wsc__SecurityContextToken->wsu__Id)
  { const char *URI = soap_wsse_get_KeyInfo_SecurityTokenReferenceURI(soap);
    if (URI && !strcmp(URI, security->wsc__SecurityContextToken->wsu__Id))
      return security->wsc__SecurityContextToken->Identifier;
  }
  return NULL;
}

/******************************************************************************\
 *
 * ds:Signature/SignedInfo
 *
\******************************************************************************/

/**
@fn ds__SignedInfoType* soap_wsse_add_SignedInfo(struct soap *soap)
@brief Adds SignedInfo element.
@param soap context
@return ds__SignedInfoType object
*/
struct ds__SignedInfoType*
soap_wsse_add_SignedInfo(struct soap *soap)
{ ds__SignatureType *signature = soap_wsse_add_Signature(soap);
  if (!signature->SignedInfo)
  { signature->SignedInfo = (ds__SignedInfoType*)soap_malloc(soap, sizeof(ds__SignedInfoType));
    if (!signature->SignedInfo)
      return NULL;
    soap_default_ds__SignedInfoType(soap, signature->SignedInfo);
  }
  return signature->SignedInfo;
}

/**
@fn int soap_wsse_add_SignedInfo_Reference(struct soap *soap, const char *URI, const char *transform, const char *inclusiveNamespaces, int alg, const char *HA)
@brief Adds SignedInfo element with Reference URI, transform algorithm used, and digest value.
@param soap context
@param[in] URI reference
@param[in] transform string should be c14n_URI for exc-c14n or NULL
@param[in] inclusiveNamespaces used by the exc-c14n transform or NULL
@param[in] alg is the digest algorithm used
@param[in] HA is the digest in binary form
@return SOAP_OK or SOAP_EOM when references exceed SOAP_WSSE_MAX_REF

This function can be called to add more references to the wsse:SignedInfo
element. A maximum number of SOAP_WSSE_MAX_REF references can be added. The
digest method is always SHA1. 
Note: XPath transforms cannot be specified in this release.
*/
int
soap_wsse_add_SignedInfo_Reference(struct soap *soap, const char *URI, const char *transform, const char *inclusiveNamespaces, int alg, const char *HA)
{ ds__SignedInfoType *signedInfo = soap_wsse_add_SignedInfo(soap);
  ds__ReferenceType *reference;
  DBGFUN3("soap_wsse_add_SignedInfo_Reference", "URI=%s", URI?URI:"", "transform=%s", transform?transform:"", "alg=%x", alg);
  /* if this is the first reference, allocate SOAP_WSSE_MAX_REF references */
  if (signedInfo->__sizeReference == 0)
    signedInfo->Reference = (ds__ReferenceType**)soap_malloc(soap, SOAP_WSSE_MAX_REF*sizeof(ds__ReferenceType*));
  else
  { /* maximum number of references exceeded? */
    if (signedInfo->__sizeReference >= SOAP_WSSE_MAX_REF)
      return soap->error = SOAP_EOM;
  }
  /* allocate fresh new reference */
  reference = (ds__ReferenceType*)soap_malloc(soap, sizeof(ds__ReferenceType));
  if (!reference)
    return soap->error = SOAP_EOM;
  soap_default_ds__ReferenceType(soap, reference);
  /* populate the URI */
  reference->URI = soap_strdup(soap, URI);
  /* if a transform algorithm was used, populate the Transforms element */
  if (transform)
  { reference->Transforms = (ds__TransformsType*)soap_malloc(soap, sizeof(ds__TransformsType));
    if (!reference->Transforms)
      return soap->error = SOAP_EOM;
    soap_default_ds__TransformsType(soap, reference->Transforms);
    /* only one transform */
    reference->Transforms->__sizeTransform = 1;
    reference->Transforms->Transform = (ds__TransformType*)soap_malloc(soap, sizeof(ds__TransformType));
    soap_default_ds__TransformType(soap, reference->Transforms->Transform);
    reference->Transforms->Transform->Algorithm = (char*)transform;
    /* populate the c14n:InclusiveNamespaces element */
    if (inclusiveNamespaces && *inclusiveNamespaces)
    { reference->Transforms->Transform->c14n__InclusiveNamespaces = (_c14n__InclusiveNamespaces*)soap_malloc(soap, sizeof(_c14n__InclusiveNamespaces));
      if (!reference->Transforms->Transform->c14n__InclusiveNamespaces)
        return soap->error = SOAP_EOM;
      soap_default__c14n__InclusiveNamespaces(soap, reference->Transforms->Transform->c14n__InclusiveNamespaces);
      reference->Transforms->Transform->c14n__InclusiveNamespaces->PrefixList = soap_strdup(soap, inclusiveNamespaces);
    }
  }
  /* populate the DigestMethod element */
  reference->DigestMethod = (ds__DigestMethodType*)soap_malloc(soap, sizeof(ds__DigestMethodType));
  if (!reference->DigestMethod)
    return soap->error = SOAP_EOM;
  soap_default_ds__DigestMethodType(soap, reference->DigestMethod);
  /* the DigestMethod algorithm SHA1, SHA256, SHA512  */
  switch (alg & SOAP_SMD_HASH)
  { case SOAP_SMD_SHA1:
      reference->DigestMethod->Algorithm = (char*)ds_sha1URI;
      break;
    case SOAP_SMD_SHA256:
      reference->DigestMethod->Algorithm = (char*)ds_sha256URI;
      break;
    case SOAP_SMD_SHA512:
      reference->DigestMethod->Algorithm = (char*)ds_sha512URI;
      break;
  }
  /* populate the DigestValue element */
  reference->DigestValue = soap_s2base64(soap, (unsigned char*)HA, NULL, soap_smd_size(alg, NULL));
  if (!reference->DigestValue)
    return soap->error;
  /* add the fresh new reference to the array */
  signedInfo->Reference[signedInfo->__sizeReference] = reference;
  signedInfo->__sizeReference++;
  return SOAP_OK;
}

/**
@fn int soap_wsse_add_SignedInfo_SignatureMethod(struct soap *soap, const char *method, int canonical)
@brief Adds SignedInfo element with SignatureMethod.
@param soap context
@param[in] method is the URI of the signature algorithm (e.g. ds_rsa_sha1)
@param[in] canonical flag indicating that SignedInfo is signed in exc-c14n form
@return SOAP_OK

Note: the c14n:InclusiveNamespaces/PrefixList is set to "SOAP-ENV wsse".
*/
int
soap_wsse_add_SignedInfo_SignatureMethod(struct soap *soap, const char *method, int canonical)
{ ds__SignedInfoType *signedInfo = soap_wsse_add_SignedInfo(soap);
  DBGFUN2("soap_wsse_add_SignedInfo_SignatureMethod", "method=%s", method?method:"", "canonical=%d", canonical);
  /* if signed in exc-c14n form, populate CanonicalizationMethod element */
  signedInfo->CanonicalizationMethod = (ds__CanonicalizationMethodType*)soap_malloc(soap, sizeof(ds__CanonicalizationMethodType));
  if (!signedInfo->CanonicalizationMethod)
    return soap->error = SOAP_EOM;
  soap_default_ds__CanonicalizationMethodType(soap, signedInfo->CanonicalizationMethod);
  if (canonical)
  { signedInfo->CanonicalizationMethod->Algorithm = (char*)c14n_URI;
    /* 
    signedInfo->CanonicalizationMethod->c14n__InclusiveNamespaces = (_c14n__InclusiveNamespaces*)soap_malloc(soap, sizeof(_c14n__InclusiveNamespaces));
    soap_default__c14n__InclusiveNamespaces(soap, signedInfo->CanonicalizationMethod->c14n__InclusiveNamespaces);
    signedInfo->CanonicalizationMethod->c14n__InclusiveNamespaces->PrefixList = "SOAP-ENV wsse";
    */
  }
  /* populate SignatureMethod element */
  signedInfo->SignatureMethod = (ds__SignatureMethodType*)soap_malloc(soap, sizeof(ds__SignatureMethodType));
  if (!signedInfo->SignatureMethod)
    return soap->error = SOAP_EOM;
  soap_default_ds__SignatureMethodType(soap, signedInfo->SignatureMethod);
  signedInfo->SignatureMethod->Algorithm = (char*)method;
  return SOAP_OK;
}

/**
@fn ds__SignedInfoType* soap_wsse_SignedInfo(struct soap *soap)
@brief Returns SignedInfo element if present.
@param soap context
@return ds__SignedInfoType object or NULL
*/
struct ds__SignedInfoType*
soap_wsse_SignedInfo(struct soap *soap)
{ ds__SignatureType *signature = soap_wsse_Signature(soap);
  if (signature)
    return signature->SignedInfo;
  return NULL;
}

/**
@fn int soap_wsse_get_SignedInfo_SignatureMethod(struct soap *soap, int *alg)
@brief Get SignatureMethod algorithm
@param soap context
@param[out] alg is a signature algorithm, such as SOAP_SMD_HMAC_SHA1, SOAP_SMD_VRFY_DSA_SHA1, or SOAP_SMD_VRFY_RSA_SHA1
@return SOAP_OK or SOAP_FAULT with wsse:UnsupportedAlgorithm or wsse:FailedCheck fault
*/
int
soap_wsse_get_SignedInfo_SignatureMethod(struct soap *soap, int *alg)
{ ds__SignedInfoType *signedInfo = soap_wsse_SignedInfo(soap);
  DBGFUN("soap_wsse_get_SignedInfo_SignatureMethod");
  *alg = SOAP_SMD_NONE;
  /* if we have a SignedInfo element, get the algorithm */
  if (signedInfo
   && signedInfo->SignatureMethod
   && signedInfo->SignatureMethod->Algorithm)
  { const char *method = signedInfo->SignatureMethod->Algorithm;
    if (!strcmp(method, ds_hmac_sha1URI))
      *alg = SOAP_SMD_HMAC_SHA1;
    else if (!strcmp(method, ds_hmac_sha256URI))
      *alg = SOAP_SMD_HMAC_SHA256;
    else if (!strcmp(method, ds_hmac_sha512URI))
      *alg = SOAP_SMD_HMAC_SHA512;
    else if (!strcmp(method, ds_dsa_sha1URI))
      *alg = SOAP_SMD_VRFY_DSA_SHA1;
    else if (!strcmp(method, ds_rsa_sha1URI))
      *alg = SOAP_SMD_VRFY_RSA_SHA1;
    else if (!strcmp(method, ds_rsa_sha256URI))
      *alg = SOAP_SMD_VRFY_RSA_SHA256;
    else if (!strcmp(method, ds_rsa_sha512URI))
      *alg = SOAP_SMD_VRFY_RSA_SHA512;
    else
      return soap_wsse_fault(soap, wsse__UnsupportedAlgorithm, method);
    return SOAP_OK;
  }
  return soap_wsse_fault(soap, wsse__FailedCheck, "Signature required");
}

/******************************************************************************\
 *
 * ds:Signature/SignatureValue
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_SignatureValue(struct soap *soap, int alg, const void *key, int keylen)
@brief Adds SignedInfo/SignatureMethod element, signs the SignedInfo element, and adds the resulting SignatureValue element.
@param soap context
@param[in] alg is SOAP_SMD_HMAC_SHA1, SOAP_SMD_SIGN_DSA_SHA1, or SOAP_SMD_SIGN_RSA_SHA1
@param[in] key to use to sign (HMAC or EVP_PKEY)
@param[in] keylen length of HMAC key
@return SOAP_OK, SOAP_EOM, or fault

To sign the SignedInfo element with this function, populate SignedInfo with
Reference elements first using soap_wsse_add_SignedInfo_Reference. The
SignedInfo element must not be modified after signing.

The SOAP_XML_INDENT and SOAP_XML_CANONICAL flags are used to serialize the
SignedInfo to compute the signature.
*/
int
soap_wsse_add_SignatureValue(struct soap *soap, int alg, const void *key, int keylen)
{ ds__SignatureType *signature = soap_wsse_add_Signature(soap);
  const char *method = NULL;
  char *sig;
  int siglen;
  int err;
  DBGFUN1("soap_wsse_add_SignatureValue", "alg=%x", alg);
  /* determine signature algorithm to use */
  switch (alg)
  { case SOAP_SMD_HMAC_SHA1:
      method = ds_hmac_sha1URI;
      break;
    case SOAP_SMD_HMAC_SHA256:
      method = ds_hmac_sha256URI;
      break;
    case SOAP_SMD_HMAC_SHA512:
      method = ds_hmac_sha512URI;
      break;
    case SOAP_SMD_SIGN_DSA_SHA1:
      method = ds_dsa_sha1URI;
      break;
    case SOAP_SMD_SIGN_RSA_SHA1:
      method = ds_rsa_sha1URI;
      break;
    case SOAP_SMD_SIGN_RSA_SHA256:
      method = ds_rsa_sha256URI;
      break;
    case SOAP_SMD_SIGN_RSA_SHA512:
      method = ds_rsa_sha512URI;
      break;
    default:
      return soap_wsse_fault(soap, wsse__UnsupportedAlgorithm, NULL);
  }
  /* populate SignedInfo/SignatureMethod based on SOAP_XML_CANONICAL flag */
  soap_wsse_add_SignedInfo_SignatureMethod(soap, method, (soap->mode & SOAP_XML_CANONICAL));
  /* use the gSOAP engine's look-aside buffer to temporarily hold the sig */
  if (soap_store_lab(soap, NULL, soap_smd_size(alg, key)))
    return soap->error = SOAP_EOM;
  sig = soap->labbuf;
  /* we will serialize SignedInfo as it appears exactly in the SOAP Header */
  /* set indent level for XML SignedInfo as it appears in the SOAP Header */
  soap->level = 4;
  /* prevent xmlns:ds namespace inclusion when non-exclusive is used */
  if (!(soap->mode & SOAP_XML_CANONICAL))
    soap_push_namespace(soap, "ds", ds_URI);
  /* use smdevp engine to sign SignedInfo */
  err = soap_smd_begin(soap, alg, key, keylen);
  if (!err)
    err = soap_out_ds__SignedInfoType(soap, "ds:SignedInfo", 0, signature->SignedInfo, NULL);
  if (soap_smd_end(soap, sig, &siglen) || err)
    return soap_wsse_fault(soap, wsse__InvalidSecurity, "Could not sign");
  /* populate the SignatureValue element */
  signature->SignatureValue = soap_s2base64(soap, (unsigned char*)sig, NULL, siglen);
  if (!signature->SignatureValue)
    return soap->error;
  return SOAP_OK;
}

/**
@fn int soap_wsse_verify_SignatureValue(struct soap *soap, int alg, const void *key, int keylen)
@brief Verifies the SignatureValue of a SignedInfo element.
@param soap context
@param[in] alg is a signature algorith, such as SOAP_SMD_HMAC_SHA1, SOAP_SMD_VRFY_DSA_SHA1, or SOAP_SMD_VRFY_RSA_SHA1 determined by the SignedInfo/SignatureMethod
@param[in] key to use to verify (HMAC or EVP_PKEY)
@param[in] keylen length of HMAC key
@return SOAP_OK, SOAP_EOM, or fault

This function searches for the SignedInfo element in the soap->dom DOM tree to
verify the signature in the SignatureValue element. Using the DOM ensures we
will verify the signature of a SignedInfo as it was exactly received by the
parser, by using the -DWITH_DOM compile flag and SOAP_XML_DOM runtime flag. If
there is no DOM, it verifies the signature of the deserialized SignedInfo
element in the SOAP Header. However, serializing deserialized data may change
the octet stream that was signed, unless we're using gSOAP as producers and
consumers (with the SOAP_XML_INDENT flag reset).
*/
int
soap_wsse_verify_SignatureValue(struct soap *soap, int alg, const void *key, int keylen)
{ ds__SignatureType *signature = soap_wsse_Signature(soap);
  DBGFUN1("soap_wsse_verify_SignatureValue", "alg=%x", alg);
  /* always need an HMAC secret key or DSA/RSA public key to verify */
  if (!key)
    return soap_wsse_fault(soap, wsse__SecurityTokenUnavailable, NULL);
  /* verify the SignedInfo element with the SignatureValue element */
  if (signature
   && signature->SignedInfo
   && signature->SignatureValue)
  { char *sig;
    const char *sigval;
    int method, siglen, sigvallen;
    /* check that we are using the intended signature algorithm */
    if (soap_wsse_get_SignedInfo_SignatureMethod(soap, &method))
      return soap->error;
    if (alg != method)
      return soap_wsse_fault(soap, wsse__FailedCheck, "Incorrect signature algorithm used");
    /* retrieve the signature */
    sigval = soap_base642s(soap, signature->SignatureValue, NULL, 0, &sigvallen);
    /* search the DOM for SignedInfo */
    if (soap->dom)
    { struct soap_dom_element *elt;
      /* traverse the DOM while searching for SignedInfo in the ds namespace */
      for (elt = soap->dom; elt; elt = soap_dom_next_element(elt))
      { if (elt->name
         && elt->nstr
         && !strcmp(elt->nstr, ds_URI)
         && (!strcmp(elt->name, "SignedInfo") || !soap_tag_cmp(elt->name, "*:SignedInfo")))
          break;
      }
      /* found it? */
      if (elt)
      { int err = SOAP_OK;
        /* should not include leading whitespace in signature verification */
        elt->head = NULL;
        /* use smdevp engine to verify SignedInfo */
        if ((alg & SOAP_SMD_ALGO) == SOAP_SMD_HMAC)
          sig = (char*)soap_malloc(soap, soap_smd_size(alg, key));
	else
        { sig = (char*)sigval;
          siglen = sigvallen;
        }
        if (signature->SignedInfo->CanonicalizationMethod
	 && signature->SignedInfo->CanonicalizationMethod->Algorithm
	 && !strcmp(signature->SignedInfo->CanonicalizationMethod->Algorithm, c14n_URI))
        { struct soap_dom_element *prt;
	  struct soap_dom_attribute *att;
          /* recanonicalize DOM while keeping content "as is" */
          DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Verifying signed canonicalized DOM\n"));
	  soap->mode &= ~SOAP_XML_DOM;
	  soap->mode |= SOAP_XML_CANONICAL | SOAP_DOM_ASIS;
          err = soap_smd_begin(soap, alg, key, keylen);
          /* emit all xmlns attributes of ancestors */
          while (soap->nlist)
          { register struct soap_nlist *np = soap->nlist->next;
            SOAP_FREE(soap, soap->nlist);
            soap->nlist = np;
          }
          /* TODO: consider moving this into dom.cpp */
	  for (prt = elt->prnt; prt; prt = prt->prnt)
          { for (att = prt->atts; att; att = att->next)
              if (!strncmp(att->name, "xmlns:", 6) && !soap_lookup_ns(soap, att->name + 6, strlen(att->name + 6)))
                soap_attribute(soap, att->name, att->data);
          }
	  for (prt = elt->prnt; prt; prt = prt->prnt)
          { for (att = prt->atts; att; att = att->next)
              if (!strcmp(att->name, "xmlns"))
	      { soap_attribute(soap, att->name, att->data);
	        break;
	      }
	  }
	}
	else
        { /* compute digest over DOM "as is" */
          soap->mode &= ~(SOAP_XML_CANONICAL | SOAP_XML_DOM);
          soap->mode |= SOAP_DOM_ASIS;
          err = soap_smd_begin(soap, alg, key, keylen);
	}
	/* do not dump namespace table xmlns bindings */
	soap->ns = 2;
        /* compute digest */
        soap->feltbegout = NULL;
        soap->feltendout = NULL;
        if (!err)
          err = soap_out_xsd__anyType(soap, NULL, 0, elt, NULL);
        if (soap_smd_end(soap, sig, &siglen) || err)
          return soap_wsse_fault(soap, wsse__FailedCheck, "The signed SignedInfo SignatureValue is invalid");
        if ((alg & SOAP_SMD_ALGO) == SOAP_SMD_HMAC)
        { if (siglen != sigvallen || memcmp(sig, sigval, siglen))
            return soap_wsse_fault(soap, wsse__FailedCheck, "The HMAC-signed SignedInfo is invalid");
        }
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Signature in DOM is valid\n"));
        return SOAP_OK;
      }
    }
    else
    { int err = SOAP_OK;
      const char *c14nexclude;
      soap_mode mode;
      /* serialize the SignedInfo element as it appeared in the SOAP Header */
      soap->level = 4;
      c14nexclude = soap->c14nexclude;
      soap->c14nexclude = "ds";
      mode = soap->mode;
      if (signature->SignedInfo->CanonicalizationMethod)
        soap->mode |= SOAP_XML_CANONICAL;
      else
        soap->mode &= ~SOAP_XML_CANONICAL;
      if ((alg & SOAP_SMD_ALGO) == SOAP_SMD_HMAC)
        sig = (char*)soap_malloc(soap, soap_smd_size(alg, key));
      else
      { sig = (char*)sigval;
        siglen = sigvallen;
      }
      err = soap_smd_begin(soap, alg, key, keylen);
      if (!err)
        err = soap_out_ds__SignedInfoType(soap, "ds:SignedInfo", 0, signature->SignedInfo, NULL);
      soap->mode = mode;
      soap->c14nexclude = c14nexclude;
      if (soap_smd_end(soap, sig, &siglen) || err)
        return soap_wsse_fault(soap, wsse__FailedCheck, "The signed serialized SignedInfo SignatureValue is invalid");
      if ((alg & SOAP_SMD_ALGO) == SOAP_SMD_HMAC)
      { if (siglen != sigvallen || memcmp(sig, sigval, siglen))
          return soap_wsse_fault(soap, wsse__FailedCheck, "The HMAC-signed serialized SignedInfo is invalid");
      }
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Signature is valid\n"));
      return SOAP_OK;
    }
  }
  return soap_wsse_fault(soap, wsse__FailedCheck, "SignedInfo required");
}

/**
@fn int soap_wsse_verify_SignedInfo(struct soap *soap)
@brief Verifies the digest values of the XML elements referenced by the SignedInfo References.
@param soap context
@return SOAP_OK or fault

This function searches for the SignedInfo element in the soap->dom DOM tree to
verify the digests contained therein. Using the DOM ensures we will verify the
digests of the locally signed elements as they were exactly received by the
parser, by using the -DWITH_DOM compile flag and SOAP_XML_DOM runtime flag. If
there is no DOM, the function fails.
*/
int
soap_wsse_verify_SignedInfo(struct soap *soap)
{ ds__SignedInfoType *signedInfo = soap_wsse_SignedInfo(soap);
  DBGFUN("soap_wsse_verify_SignedInfo");
  if (signedInfo)
  { int i;
    /* must have at least one reference element */
    if (signedInfo->__sizeReference == 0)
      return soap_wsse_fault(soap, wsse__InvalidSecurity, "Missing SignedInfo/Reference");
    /* As an alternative to the current implementatin, this might be a good place to re-canonicalize the entire DOM to improve interop. Two DOMs can be used: one with non-c14n XML and one with c14n XML so we can handle multiple different transforms. */
    /* for each reference element, check the digest */
    for (i = 0; i < signedInfo->__sizeReference; i++)
    { ds__ReferenceType *reference = signedInfo->Reference[i];
      /* reference element is complete? */
      if (!reference->URI
       || !reference->DigestMethod
       || !reference->DigestMethod->Algorithm
       || !reference->DigestValue)
        return soap_wsse_fault(soap, wsse__InvalidSecurity, "Incomplete SignedInfo/Reference");
      /* reference is local? */
      if (*reference->URI == '#')
      { int alg, canonical;
        unsigned char hash[SOAP_SMD_MAX_SIZE];
        /* digest algorithm */
        if (!strcmp(reference->DigestMethod->Algorithm, ds_sha1URI))
          alg = SOAP_SMD_DGST_SHA1;
        else if (!strcmp(reference->DigestMethod->Algorithm, ds_sha256URI))
          alg = SOAP_SMD_DGST_SHA256;
        else if (!strcmp(reference->DigestMethod->Algorithm, ds_sha512URI))
          alg = SOAP_SMD_DGST_SHA512;
        else
          return soap_wsse_fault(soap, wsse__UnsupportedAlgorithm, reference->DigestMethod->Algorithm);
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Verifying digest of locally referenced data %s alg=%x\n", reference->URI, alg));
        /* if reference has a transform, it should be an exc-c14n transform */
        if (reference->Transforms)
	{ if (reference->Transforms->__sizeTransform != 1
           || !reference->Transforms->Transform[0].Algorithm
           || strcmp(reference->Transforms->Transform[0].Algorithm, c14n_URI))
            return soap_wsse_fault(soap, wsse__UnsupportedAlgorithm, reference->Transforms->Transform[0].Algorithm);
	  canonical = 1;
	}
	else
	  canonical = 0;
        /* convert base64 digest to binary */
        soap_base642s(soap, reference->DigestValue, (char*)hash, SOAP_SMD_MAX_SIZE, NULL);
        /* verify the digest of a locally signed element */
        if (soap_wsse_verify_digest(soap, alg, canonical, reference->URI + 1, hash))
          return soap->error;
      }
    }
    return SOAP_OK;
  }
  return soap_wsse_fault(soap, wsse__InvalidSecurity, "Missing SignedInfo");
}

/**
@fn int soap_wsse_verify_digest(struct soap *soap, int alg, int canonical, const char *id, unsigned char hash[SOAP_SMD_MAX_SIZE])
@brief Verifies the digest value of an XML element referenced by id against the hash.
@param soap context
@param[in] alg digest algorithm
@param[in] canonical flag indicating that element is signed in exc-c14n form
@param[in] id string of the XML element to verify
@param[in] hash digest value to verify against
@return SOAP_OK or fault
*/
int
soap_wsse_verify_digest(struct soap *soap, int alg, int canonical, const char *id, unsigned char hash[SOAP_SMD_MAX_SIZE])
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  struct soap_dom_element *elt, *dom = NULL;
  DBGFUN3("soap_wsse_verify_digest", "alg=%x", alg, "canonical=%d", canonical, "id=%s", id);
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_verify_digest", "Plugin not registered", SOAP_PLUGIN_ERROR);
  /* traverse the DOM to find the element with matching wsu:Id or ds:Id */
  for (elt = soap->dom; elt; elt = soap_dom_next_element(elt))
  { struct soap_dom_attribute *att;
    for (att = elt->atts; att; att = att->next)
    { /* check attribute */
      if (att->name
       && att->nstr
       && (!strcmp(att->nstr, wsu_URI) || !strcmp(att->nstr, ds_URI))
       && (!strcmp(att->name, "Id") || !soap_tag_cmp(att->name, "*:Id")))
      { /* found a match, compare attribute value with id */
        if (att->data && !strcmp(att->data, id))
        { if (dom)
            return soap_wsse_fault(soap, wsse__FailedCheck, "SignedInfo duplicate Id");
	  dom = elt;
	  /* elt = NULL; break; */ /* improves speed but skips duplicate Id check */
        }
      }
    }
  }
  if (dom)
  { unsigned char HA[SOAP_SMD_MAX_SIZE];
    int len, err = SOAP_OK;
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Computing digest for Id=%s\n", id));
    /* do not hash leading whitespace */
    dom->head = NULL;
    /* canonical or as-is? */
    if (canonical)
    { struct soap_dom_element *prt;
      struct soap_dom_attribute *att;
      soap->mode |= SOAP_XML_CANONICAL | SOAP_DOM_ASIS;
      err = soap_smd_begin(soap, alg, NULL, 0);
      /* emit all xmlns attributes of ancestors */
      while (soap->nlist)
      { register struct soap_nlist *np = soap->nlist->next;
        SOAP_FREE(soap, soap->nlist);
        soap->nlist = np;
      }
      /* TODO: consider moving this into dom.cpp */
      for (prt = dom->prnt; prt; prt = prt->prnt)
      { for (att = prt->atts; att; att = att->next)
        { if (!strncmp(att->name, "xmlns:", 6) && !soap_lookup_ns(soap, att->name + 6, strlen(att->name + 6)))
          { DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Attribute=%s\n", att->name));
            soap_attribute(soap, att->name, att->data);
          }
        }
      }
      for (prt = dom->prnt; prt; prt = prt->prnt)
      { for (att = prt->atts; att; att = att->next)
        { if (!strcmp(att->name, "xmlns"))
          { soap_attribute(soap, att->name, att->data);
            break;
          }
        }
      }
    }
    else
    { /* compute digest over DOM "as is" */
      soap->mode &= ~SOAP_XML_CANONICAL;
      soap->mode |= SOAP_DOM_ASIS;
      err = soap_smd_begin(soap, alg, NULL, 0);
    }
    /* do not dump namespace table xmlns bindings */
    soap->ns = 2;
    /* compute digest */
    soap->feltbegout = NULL;
    soap->feltendout = NULL;
    if (!err)
      err = soap_out_xsd__anyType(soap, NULL, 0, dom, NULL);
    if (soap_smd_end(soap, (char*)HA, &len) || err)
      return soap_wsse_fault(soap, wsse__FailedCheck, "Digest computation failed");
    /* compare digests, success if identical */
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Comparing digest hashes\n"));
    DBGHEX(TEST, hash, len);
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "\n--\n"));
    DBGHEX(TEST, HA, len);
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "\n"));
    if (!memcmp(hash, HA, (size_t)len))
      return SOAP_OK;
    return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
  }
  if (data->vrfy_alg & SOAP_WSSE_IGNORE_EXTRA_REFS)
    return SOAP_OK;
  return soap_wsse_fault(soap, wsse__FailedCheck, "SignedInfo reference URI target not found");
}

/******************************************************************************\
 *
 * ds:Signature/KeyInfo
 *
\******************************************************************************/

/**
@fn ds__KeyInfoType* soap_wsse_add_KeyInfo(struct soap *soap)
@brief Adds KeyInfo element.
@param soap context
@return ds__KeyInfo object
*/
struct ds__KeyInfoType*
soap_wsse_add_KeyInfo(struct soap *soap)
{ ds__SignatureType *signature = soap_wsse_add_Signature(soap);
  if (!signature->KeyInfo)
  { signature->KeyInfo = (ds__KeyInfoType*)soap_malloc(soap, sizeof(ds__KeyInfoType));
    if (!signature->KeyInfo)
      return NULL;
  }
  soap_default_ds__KeyInfoType(soap, signature->KeyInfo);
  return signature->KeyInfo;
}

/**
@fn ds__KeyInfoType* soap_wsse_KeyInfo(struct soap *soap)
@brief Returns KeyInfo element if present.
@param soap context
@return ds__KeyInfo object or NULL
*/
struct ds__KeyInfoType*
soap_wsse_KeyInfo(struct soap *soap)
{ ds__SignatureType *signature = soap_wsse_Signature(soap);
  if (signature)
    return signature->KeyInfo;
  return NULL;
}

/******************************************************************************\
 *
 * ds:Signature/KeyInfo/KeyName
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_KeyInfo_KeyName(struct soap *soap, const char *name)
@brief Adds KeyName element.
@param soap context
@param[in] name string of the KeyName
@return SOAP_OK

Note: the recommended method to add Key information is to utilize KeyIdentifier
instead of KeyName. A KeyName is useful mainly for internal use.
*/
int
soap_wsse_add_KeyInfo_KeyName(struct soap *soap, const char *name)
{ ds__KeyInfoType *keyInfo = soap_wsse_add_KeyInfo(soap);
  DBGFUN1("soap_wsse_add_KeyInfo_KeyName", "name=%s", name);
  /* populate the KeyName element */
  keyInfo->KeyName = soap_strdup(soap, name);
  return SOAP_OK;
}

/**
@fn int soap_wsse_get_KeyInfo_KeyName(struct soap *soap)
@brief Returns KeyName element if present.
@param soap context
@return string or NULL
*/
const char*
soap_wsse_get_KeyInfo_KeyName(struct soap *soap)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  DBGFUN("soap_wsse_get_KeyInfo_KeyName");
  if (!keyInfo)
    return NULL;
  return keyInfo->KeyName;
}

/******************************************************************************\
 *
 * ds:Signature/KeyInfo/wsse:SecurityTokenReference/Reference/@URI
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_KeyInfo_SecurityTokenReferenceURI(struct soap *soap, const char *URI, const char *valueType)
@brief Adds KeyInfo element with SecurityTokenReference URI.
@param soap context
@param[in] URI string referencing a security token
@param[in] valueType string or NULL
@return SOAP_OK
*/
int
soap_wsse_add_KeyInfo_SecurityTokenReferenceURI(struct soap *soap, const char *URI, const char *valueType)
{ ds__KeyInfoType *keyInfo = soap_wsse_add_KeyInfo(soap);
  DBGFUN2("soap_wsse_add_KeyInfo_SecurityTokenReferenceURI", "URI=%s", URI?URI:"", "valueType=%s", valueType?valueType:"");
  /* allocate SecurityTokenReference element if we don't have one already */
  if (!keyInfo->wsse__SecurityTokenReference)
  { keyInfo->wsse__SecurityTokenReference = (_wsse__SecurityTokenReference*)soap_malloc(soap, sizeof(_wsse__SecurityTokenReference));
    if (!keyInfo->wsse__SecurityTokenReference)
      return soap->error = SOAP_EOM;
  }
  soap_default__wsse__SecurityTokenReference(soap, keyInfo->wsse__SecurityTokenReference);
  /* allocate Reference element */
  keyInfo->wsse__SecurityTokenReference->Reference = (_wsse__Reference*)soap_malloc(soap, sizeof(_wsse__Reference));
  soap_default__wsse__Reference(soap, keyInfo->wsse__SecurityTokenReference->Reference);
  /* populate the Reference element */
  keyInfo->wsse__SecurityTokenReference->Reference->URI = soap_strdup(soap, URI);
  keyInfo->wsse__SecurityTokenReference->Reference->ValueType = soap_strdup(soap, valueType);
  return SOAP_OK;
}

/**
@fn int soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(struct soap *soap, const char *URI)
@brief Adds KeyInfo element with SecurityTokenReference URI to an X509 cert.
@param soap context
@param[in] URI string referencing an X509 certificate
@return SOAP_OK
*/
int
soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(struct soap *soap, const char *URI)
{ return soap_wsse_add_KeyInfo_SecurityTokenReferenceURI(soap, URI, wsse_X509v3URI);
}

/**
@fn const char* soap_wsse_get_KeyInfo_SecurityTokenReferenceURI(struct soap *soap)
@brief Returns a SecurityTokenReference URI if present.
@param soap context
@return string or NULL
*/
const char*
soap_wsse_get_KeyInfo_SecurityTokenReferenceURI(struct soap *soap)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  if (keyInfo
   && keyInfo->wsse__SecurityTokenReference
   && keyInfo->wsse__SecurityTokenReference->Reference)
    return keyInfo->wsse__SecurityTokenReference->Reference->URI;
  return NULL;
}

/**
@fn const char* soap_wsse_get_KeyInfo_SecurityTokenReferenceValueType(struct soap *soap)
@brief Returns a SecurityTokenReference ValueType if present.
@param soap context
@return string or NULL
*/
const char*
soap_wsse_get_KeyInfo_SecurityTokenReferenceValueType(struct soap *soap)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  if (keyInfo
   && keyInfo->wsse__SecurityTokenReference
   && keyInfo->wsse__SecurityTokenReference->Reference)
    return keyInfo->wsse__SecurityTokenReference->Reference->ValueType;
  return NULL;
}

/**
@fn X509* soap_wsse_get_KeyInfo_SecurityTokenReferenceX509(struct soap *soap)
@brief Returns a X509 certificate if present as a BinarySecurity token.
@param soap context
@return X509 object or NULL with wsse:SecurityTokenUnavailable fault
*/
X509*
soap_wsse_get_KeyInfo_SecurityTokenReferenceX509(struct soap *soap)
{ const char *URI = soap_wsse_get_KeyInfo_SecurityTokenReferenceURI(soap);
  X509 *cert = NULL;
  DBGFUN("soap_wsse_get_KeyInfo_SecurityTokenReferenceX509");
  if (URI && *URI == '#')
  { const char *valueType;
    valueType = soap_wsse_get_KeyInfo_SecurityTokenReferenceValueType(soap);
    if (!valueType || !strcmp(valueType, wsse_X509v3URI))
      cert = soap_wsse_get_BinarySecurityTokenX509(soap, URI + 1);
  }
  return cert;
}

/**
@fn struct ds__X509IssuerSerialType *soap_wsse_get_KeyInfo_SecurityTokenReferenceX509Data(struct soap *soap)
@brief Returns ds__X509IssuerSerialType with non-NULL X509IssuerName and non-NULL X509SerialNumber of a X509Data element when present and set.
@param soap context
@return pointer to ds__X509IssuerSerialType struct or NULL
*/
struct ds__X509IssuerSerialType *
soap_wsse_get_KeyInfo_SecurityTokenReferenceX509Data(struct soap *soap)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  if (keyInfo
   && keyInfo->wsse__SecurityTokenReference
   && keyInfo->wsse__SecurityTokenReference->ds__X509Data
   && keyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial
   && keyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial->X509IssuerName
   && keyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial->X509SerialNumber)
    return keyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial;
  return NULL;
}

/******************************************************************************\
 *
 * ds:Signature/KeyInfo/wsse:SecurityTokenReference/Reference/KeyIdentifier
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_KeyInfo_SecurityTokenReferenceKeyIdentifier(struct soap *soap, const char *id, const char *valueType, unsigned char *data, int size)
@brief Adds KeyInfo element with SecurityTokenReference/KeyIdentifier binary data
@param soap context
@param[in] id string for signature reference
@param[in] valueType string
@param[in] data binary data
@param[in] size of binary data
@return SOAP_OK
*/
int
soap_wsse_add_KeyInfo_SecurityTokenReferenceKeyIdentifier(struct soap *soap, const char *id, const char *valueType, unsigned char *data, int size)
{ ds__KeyInfoType *keyInfo = soap_wsse_add_KeyInfo(soap);
  DBGFUN2("soap_wsse_add_KeyInfo_SecurityTokenReferenceKeyIdentifier", "id=%s", id?id:"", "valueType=%s", valueType?valueType:"");
  /* allocate SecurityTokenReference if we don't have one already */
  if (!keyInfo->wsse__SecurityTokenReference)
  { keyInfo->wsse__SecurityTokenReference = (_wsse__SecurityTokenReference*)soap_malloc(soap, sizeof(_wsse__SecurityTokenReference));
    if (!keyInfo->wsse__SecurityTokenReference)
      return soap->error = SOAP_EOM;
  }
  soap_default__wsse__SecurityTokenReference(soap, keyInfo->wsse__SecurityTokenReference);
  /* allocate KeyIdentifier */
  keyInfo->wsse__SecurityTokenReference->KeyIdentifier = (_wsse__KeyIdentifier*)soap_malloc(soap, sizeof(_wsse__KeyIdentifier));
  if (!keyInfo->wsse__SecurityTokenReference->KeyIdentifier)
    return soap->error = SOAP_EOM;
  soap_default__wsse__KeyIdentifier(soap, keyInfo->wsse__SecurityTokenReference->KeyIdentifier);
  /* populate KeyIdentifier */
  keyInfo->wsse__SecurityTokenReference->KeyIdentifier->wsu__Id = soap_strdup(soap, id);
  keyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType = soap_strdup(soap, valueType);
  keyInfo->wsse__SecurityTokenReference->KeyIdentifier->EncodingType = (char*)wsse_Base64BinaryURI;
  keyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item = soap_s2base64(soap, data, NULL, size);
  return SOAP_OK;
}

/**
@fn const char* soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifierValueType(struct soap *soap)
@brief Returns KeyInfo/SecurityTokenReference/KeyIdentifier/ValueType if present
@param soap context
@return string or NULL
*/
const char*
soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifierValueType(struct soap *soap)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  DBGFUN("soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifierValueType");
  if (!keyInfo
   || !keyInfo->wsse__SecurityTokenReference
   || !keyInfo->wsse__SecurityTokenReference->KeyIdentifier)
    return NULL;
  return keyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType;
}

/**
@fn const unsigned char* soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifier(struct soap *soap, int *size)
@brief Returns KeyInfo/SecurityTokenReference/KeyIdentifier binary data
@param soap context
@param[out] size is set to the size of the decoded data
@return data or NULL
*/
const unsigned char*
soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifier(struct soap *soap, int *size)
{ ds__KeyInfoType *keyInfo = soap_wsse_KeyInfo(soap);
  DBGFUN("soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifier");
  if (!keyInfo
   || !keyInfo->wsse__SecurityTokenReference
   || !keyInfo->wsse__SecurityTokenReference->KeyIdentifier)
    return NULL;
  return (unsigned char*)soap_base642s(soap, keyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item, NULL, 0, size);
}

/******************************************************************************\
 *
 * ds:Signature/KeyInfo/wsse:SecurityTokenReference/Reference/Embedded
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_KeyInfo_SecurityTokenReferenceEmbedded(struct soap *soap, const char *id, const char *valueType)
@brief Adds KeyInfo element with Embedded SecurityTokenReference.
@param soap context
@param[in] id string for signature reference
@param[in] valueType string
@return SOAP_OK

Note: this function does not add embedded tokens automatically. See code for comments.
*/
int
soap_wsse_add_KeyInfo_SecurityTokenReferenceEmbedded(struct soap *soap, const char *id, const char *valueType)
{ ds__KeyInfoType *keyInfo = soap_wsse_add_KeyInfo(soap);
  DBGFUN("soap_wsse_get_KeyInfo_SecurityTokenReferenceEmbedded");
  /* allocate SecurityTokenReference if we don't have one already */
  if (!keyInfo->wsse__SecurityTokenReference)
  { keyInfo->wsse__SecurityTokenReference = (_wsse__SecurityTokenReference*)soap_malloc(soap, sizeof(_wsse__SecurityTokenReference));
    if (!keyInfo->wsse__SecurityTokenReference)
      return soap->error = SOAP_EOM;
  }
  soap_default__wsse__SecurityTokenReference(soap, keyInfo->wsse__SecurityTokenReference);
  /* allocate Embedded element */
  keyInfo->wsse__SecurityTokenReference->Embedded = (_wsse__Embedded*)soap_malloc(soap, sizeof(_wsse__Embedded));
  if (!keyInfo->wsse__SecurityTokenReference->Embedded)
    return soap->error = SOAP_EOM;
  soap_default__wsse__Embedded(soap, keyInfo->wsse__SecurityTokenReference->Embedded);
  /* populate Embedded element */
  keyInfo->wsse__SecurityTokenReference->Embedded->wsu__Id = soap_strdup(soap, id);
  keyInfo->wsse__SecurityTokenReference->Embedded->ValueType = soap_strdup(soap, valueType);
  /* TODO: Add embedded tokens and assertions. Could use DOM here?
  keyInfo->wsse__SecurityTokenReference->Embedded->xyz = ...;
  */
  return SOAP_OK;
}

/******************************************************************************\
 *
 * wsse:Security/xenc:EncryptedKey header element
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_EncryptedKey(struct soap *soap, int alg, const char *URI, X509 *cert, const char *subjectkeyid, const char *issuer, const char *serial)
@brief Adds EncryptedKey header element and initiates the encryption of the
SOAP Body.
@param soap context
@param[in] alg algorithm to use, SOAP_MEC_ENV_ENC_DES_CBC or SOAP_MEC_ENV_ENC_AEAS256_CBC
@param[in] URI a unique identifier for the key, required for interoperability
@param[in] cert the X509 certificate with public key or NULL
@param[in] subjectkeyid string identification of the subject which when set to non-NULL is used instead of embedding the public key in the message
@param[in] issuer string to include SecurityTokenReference/X509Data 
@param[in] serial string to include SecurityTokenReference/X509Data
@return SOAP_OK or error code

This function adds the encrypted key or subject key ID to the WS-Security
header and initiates encryption of the SOAP Body. An X509 certificate may be
provided, or the subjectkeyid, or the issuer and serial number. The certificate
is embedded in the WS-Security EncryptedKey header. If the subjectkeyid string
is non-NULL the subject key ID is used in the EncryptedKey header instead of
the X509 certificate content.
*/
int
soap_wsse_add_EncryptedKey(struct soap *soap, int alg, const char *URI, X509 *cert, const char *subjectkeyid, const char *issuer, const char *serial)
{ return soap_wsse_add_EncryptedKey_encrypt_only(soap, alg, URI, cert, subjectkeyid, issuer, serial, NULL);
}

/**
@fn int soap_wsse_add_EncryptedKey_encrypt_only(struct soap *soap, int alg, const char *URI, X509 *cert, const char *subjectkeyid, const char *issuer, const char *serial, const char *tags)
@brief Adds EncryptedKey header element and initiates encryption of the given
XML elements specified in the tags string. Should be used in combination with
soap_wsse_set_wsu_id to set wsu:Id for given XML element tags. 
@param soap context
@param[in] alg algorithm to use, SOAP_MEC_ENV_ENC_DES_CBC or SOAP_MEC_ENV_ENC_AEAS256_CBC
@param[in] URI a unique identifier for the key, required for interoperability
@param[in] cert the X509 certificate with public key or NULL
@param[in] subjectkeyid string identification of the subject which when set to non-NULL is used instead of embedding the public key in the message
@param[in] issuer string to include SecurityTokenReference/X509Data 
@param[in] serial string to include SecurityTokenReference/X509Data
@param[in] tags space-separated string of element tag names to encrypt
@return xenc__EncryptedKeyType object

This function adds the encrypted key or subject key ID to the WS-Security
header and initiates encryption of the SOAP Body. An X509 certificate may be
provided, or the subjectkeyid, or the issuer and serial number. The certificate
is embedded in the WS-Security EncryptedKey header. If the subjectkeyid string
is non-NULL the subject key ID is used in the EncryptedKey header instead of
the X509 certificate content. Only the XML elements given in the 'tags' string
as wsu:Id attributed elements are encrypted.

WARNING:
Use @ref soap_wsse_add_EncryptedKey_encrypt_only only in combination with
@ref soap_wsse_set_wsu_id with the tag names of the elements to be encrypted.
OTHERWISE THE GIVEN XML ELEMENTS ARE NOT ENCRYPTED AND WILL BE SENT IN THE
CLEAR.

WARNING:
The elements identified with @ref soap_wsse_set_wsu_id to encrypt MUST occur
EXACTLY ONCE in the SOAP Body.

WARNING:
Encryption/decryption of elements with simple content (CDATA content) IS NOT
SUPPORTED. This means that elements you want to encrypt with this function must
have complex content. That is, only encrypt elements with sub elements or
encrypt the entire SOAP Body.
*/
int
soap_wsse_add_EncryptedKey_encrypt_only(struct soap *soap, int alg, const char *URI, X509 *cert, const char *subjectkeyid, const char *issuer, const char *serial, const char *tags)
{ EVP_PKEY *pubk;
  unsigned char *key;
  int keylen;
  _wsse__Security *security;
  struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_add_EncryptedKey");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_add_EncryptedKey", "Plugin not registered", SOAP_PLUGIN_ERROR);
  security = soap_wsse_add_Security(soap);
  /* if we don't have a xenc:EncryptedKey, create one */
  if (!security->xenc__EncryptedKey)
  { if (!(security->xenc__EncryptedKey = (xenc__EncryptedKeyType*)soap_malloc(soap, sizeof(xenc__EncryptedKeyType))))
      return soap->error = SOAP_EOM;
  }
  soap_default_xenc__EncryptedKeyType(soap, security->xenc__EncryptedKey); 
  security->xenc__EncryptedKey->Id = soap_strdup(soap, URI);
  if (!(security->xenc__EncryptedKey->EncryptionMethod = (xenc__EncryptionMethodType*)soap_malloc(soap, sizeof(struct xenc__EncryptionMethodType))))
    return soap->error = SOAP_EOM;
  soap_default_xenc__EncryptionMethodType(soap, security->xenc__EncryptedKey->EncryptionMethod); 
  /* RSA Version 1.5 or RSA-OAEP */
  alg |= (SOAP_MEC_ENV | SOAP_MEC_ENC);
  if (alg & SOAP_MEC_OAEP)
  { security->xenc__EncryptedKey->EncryptionMethod->Algorithm = (char*)xenc_rsaesURI;
    security->xenc__EncryptedKey->EncryptionMethod->OAEPparams = NULL;
    if (!(security->xenc__EncryptedKey->EncryptionMethod->ds__DigestMethod = (struct ds__DigestMethodType*)soap_malloc(soap, sizeof(struct ds__DigestMethodType))))
      return soap->error = SOAP_EOM;
    soap_default_ds__DigestMethodType(soap, security->xenc__EncryptedKey->EncryptionMethod->ds__DigestMethod);
    security->xenc__EncryptedKey->EncryptionMethod->ds__DigestMethod->Algorithm = (char*)ds_sha1URI;
  }
  else
    security->xenc__EncryptedKey->EncryptionMethod->Algorithm = (char*)xenc_rsa15URI;
  /* KeyInfo */
  if (!(security->xenc__EncryptedKey->ds__KeyInfo = (_ds__KeyInfo*)soap_malloc(soap, sizeof(_ds__KeyInfo))))
    return soap->error = SOAP_EOM;
  soap_default__ds__KeyInfo(soap, security->xenc__EncryptedKey->ds__KeyInfo); 
  /* allocate SecurityTokenReference */
  if (!(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference = (_wsse__SecurityTokenReference*)soap_malloc(soap, sizeof(_wsse__SecurityTokenReference))))
    return soap->error = SOAP_EOM;
  soap_default__wsse__SecurityTokenReference(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference);
  if (issuer && serial)
  { if (!(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data = (struct ds__X509DataType*)soap_malloc(soap, sizeof(struct ds__X509DataType))))
      return soap->error = SOAP_EOM;
    soap_default_ds__X509DataType(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data);
    if (!(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial = (struct ds__X509IssuerSerialType*)soap_malloc(soap, sizeof(struct ds__X509IssuerSerialType))))
      return soap->error = SOAP_EOM;
    soap_default_ds__X509IssuerSerialType(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial);
    security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial->X509IssuerName = soap_strdup(soap, issuer);
    security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->ds__X509Data->X509IssuerSerial->X509SerialNumber = soap_strdup(soap, serial);
  }
  else
  { /* allocate KeyIdentifier */
    if (!(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier = (_wsse__KeyIdentifier*)soap_malloc(soap, sizeof(_wsse__KeyIdentifier))))
      return soap->error = SOAP_EOM;
    soap_default__wsse__KeyIdentifier(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier);
    /* populate KeyIdentifier */
    security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->EncodingType = (char*)wsse_Base64BinaryURI;
    if (subjectkeyid)
    { security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType = (char*)wsse_X509v3SubjectKeyIdentifierURI;
      security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item = soap_s2base64(soap, (unsigned char*)subjectkeyid, NULL, strlen(subjectkeyid));
    }
    else if (cert)
    { unsigned char *der, *s;
      int derlen;
      security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType = (char*)wsse_X509v3URI;
      /* determine the storage requirement */
      derlen = i2d_X509(cert, NULL);
      if (derlen < 0)
        return soap_wsse_fault(soap, wsse__InvalidSecurityToken, "Invalid certificate passed to soap_wsse_add_EncryptedKey_encrypt_only");
      /* use the gSOAP engine's look-aside buffer to temporarily hold the cert */
      if (soap_store_lab(soap, NULL, derlen))
        return SOAP_EOM;
      s = der = (unsigned char*)soap->labbuf;
      /* store in DER format */
      i2d_X509(cert, &s);
      security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item = soap_s2base64(soap, der, NULL, derlen);
    }
  }
  /* CipherData */
  if (!(security->xenc__EncryptedKey->CipherData = (xenc__CipherDataType*)soap_malloc(soap, sizeof(struct xenc__CipherDataType))))
    return soap->error = SOAP_EOM;
  soap_default_xenc__CipherDataType(soap, security->xenc__EncryptedKey->CipherData); 
  /* get the public key */
  pubk = X509_get_pubkey(cert);
  if (!pubk)
    return soap_wsse_fault(soap, wsse__InvalidSecurityToken, "Invalid certificate passed to soap_wsse_add_EncryptedKey_encrypt_only");
  /* start encryption engine, get the encrypted secret key */
  key = (unsigned char*)soap_malloc(soap, soap_mec_size(alg, pubk));
  if (data->mec)
    soap_mec_cleanup(soap, data->mec);
  else
    data->mec = (struct soap_mec_data*)SOAP_MALLOC(soap, sizeof(struct soap_mec_data));
  if (soap_mec_begin(soap, data->mec, alg, pubk, key, &keylen))
  { EVP_PKEY_free(pubk);
    return soap->error;
  }
  EVP_PKEY_free(pubk);
  data->enco_alg = alg;
  data->enco_keyname = NULL;
  data->enco_key = key;
  data->enco_keylen = keylen;
  if (!(security->xenc__EncryptedKey->CipherData->CipherValue = soap_s2base64(soap, key, NULL, keylen)))
    return soap->error = SOAP_EOM;
  data->encid = soap_strdup(soap, tags);
  if (!tags)
  { soap->omode |= SOAP_SEC_WSUID;
    if (soap_wsse_add_EncryptedKey_DataReferenceURI(soap, "#Body"))
      return soap->error;
  }
  else
  { char *s, *t;
    /* make space to insert # to each id converted from a tag name */
    t = (char*)soap_malloc(soap, strlen(tags) + 2);
    if (!t)
      return soap->error = SOAP_EOM;
    *t = '#';
    strcpy(t + 1, tags);
    s = soap_wsse_ids(soap, t);
    if (!s)
      return soap->error = SOAP_EOM;
    s++;
    do
    { t = strchr(s, ' ');
      if (t)
      { *t = '\0';
        while (*++t == ' ')
          ;
      }
      *--s = '#';
      if (soap_wsse_add_EncryptedKey_DataReferenceURI(soap, s))
        return soap->error;
      s = t;
    } while (s);
  }
  soap->feltbegout = soap_wsse_element_begin_out;
  soap->feltendout = soap_wsse_element_end_out;
  return SOAP_OK;
}

/**
@fn int soap_wsse_verify_EncryptedKey(struct soap *soap)
@brief Verifies the EncryptedKey header information (certificate validity
requires soap->cacert to be set). Retrieves the decryption key from the token
handler callback to decrypt the decryption key.
@param soap context
@return SOAP_OK or error code
*/
int
soap_wsse_verify_EncryptedKey(struct soap *soap)
{  _wsse__Security *security = soap_wsse_Security(soap);
  struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_verify_EncryptedKey");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_verify_EncryptedKey", "Plugin not registered", SOAP_PLUGIN_ERROR);
  /* if we have a xenc:EncryptedKey, check it and start envelope decryption */
  if (security && security->xenc__EncryptedKey)
  { if (!security->xenc__EncryptedKey->EncryptionMethod
     || !security->xenc__EncryptedKey->EncryptionMethod->Algorithm)
      return soap_wsse_fault(soap, wsse__InvalidSecurity, "Invalid Encryption algorithm or key");
    /* verify encrypted key */
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Verify EncryptedKey alg=%x\n", data->deco_alg));
    if (security->xenc__EncryptedKey->ds__KeyInfo)
    { int keylen;
      if (security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference
       && security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier
       && security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType
       && security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item)
      { if (!strcmp(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType, wsse_X509v3URI))
        { X509 *cert = NULL;
          const unsigned char *der;
          int derlen;
          der = (unsigned char*)soap_base642s(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item, NULL, 0, &derlen);
          if (!der)
            return soap_wsse_fault(soap, wsse__InvalidSecurity, "Invalid Encryption algorithm or key");
          cert = d2i_X509(&cert, &der, derlen);
          if (soap_wsse_verify_X509(soap, cert))
          { if (cert)
              X509_free(cert);
            return soap->error;
          }
          /* get the private key from subject name of cert, if not set */
          if (!data->deco_key && data->security_token_handler)
          { char buf[1024];
	    data->deco_alg = SOAP_MEC_ENV_DEC_DES_CBC;
	    data->deco_key = data->security_token_handler(soap, &data->deco_alg, X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf)), &keylen);
	    data->deco_keylen = 0;
	  }
          if (cert)
            X509_free(cert);
        }
	else if (!data->deco_key && data->security_token_handler && !strcmp(security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->ValueType, wsse_X509v3SubjectKeyIdentifierURI))
	{ int subjectkeyidlen;
	  const char *subjectkeyid = (char*)soap_base642s(soap, security->xenc__EncryptedKey->ds__KeyInfo->wsse__SecurityTokenReference->KeyIdentifier->__item, NULL, 0, &subjectkeyidlen);
          /* get the private key from subject key id */
	  data->deco_alg = SOAP_MEC_ENV_DEC_DES_CBC;
	  data->deco_key = data->security_token_handler(soap, &data->deco_alg, subjectkeyid, &keylen);
	  data->deco_keylen = 0;
	}
      }
      else if (!data->deco_key && data->security_token_handler)
      { const char *name = NULL;
        /* get the private key from key name or subject name */
        if (security->xenc__EncryptedKey->ds__KeyInfo->KeyName)
          name = security->xenc__EncryptedKey->ds__KeyInfo->KeyName;
        else if (security->xenc__EncryptedKey->ds__KeyInfo->X509Data && security->xenc__EncryptedKey->ds__KeyInfo->X509Data->X509SubjectName)
          name = security->xenc__EncryptedKey->ds__KeyInfo->X509Data->X509SubjectName;
        if (name)
	{ data->deco_alg = SOAP_MEC_ENV_DEC_DES_CBC;
          data->deco_key = data->security_token_handler(soap, &data->deco_alg, name, &keylen);
	  data->deco_keylen = 0;
        }
      }
    }
    /* start decryption */
    if (data->deco_key && security->xenc__EncryptedKey->CipherData && security->xenc__EncryptedKey->CipherData->CipherValue)
    { int keylen;
      unsigned char *key = (unsigned char*)soap_base642s(soap, security->xenc__EncryptedKey->CipherData->CipherValue, NULL, 0, &keylen);
      if (!strcmp(security->xenc__EncryptedKey->EncryptionMethod->Algorithm, xenc_rsaesURI))
        data->deco_alg |= SOAP_MEC_OAEP;
      else if (strcmp(security->xenc__EncryptedKey->EncryptionMethod->Algorithm, xenc_rsa15URI))
        return soap_wsse_fault(soap, wsse__InvalidSecurity, "Invalid Encryption algorithm or key");
      if (data->mec)
        soap_mec_cleanup(soap, data->mec);
      else
        data->mec = (struct soap_mec_data*)SOAP_MALLOC(soap, sizeof(struct soap_mec_data));
      if (soap_mec_begin(soap, data->mec, data->deco_alg, (SOAP_MEC_KEY_TYPE*)data->deco_key, key, &keylen))
        return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
    }
    /* do not process EncryptedKey again */
    security->xenc__EncryptedKey = NULL;
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Verified EncryptedKey alg=%x\n", data->deco_alg));
  }
  return SOAP_OK;
}

/**
@fn void soap_wsse_delete_EncryptedKey(struct soap *soap)
@brief Deletes EncryptedKey header element.
@param soap context
*/
void
soap_wsse_delete_EncryptedKey(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  DBGFUN("soap_wsse_delete_EncryptedKey");
  if (security)
    security->xenc__EncryptedKey = NULL;
}

/**
@fn xenc__EncryptedKeyType* soap_wsse_EncryptedKey(struct soap *soap)
@brief Returns EncryptedKey header element if present.
@param soap context
@return xenc__EncryptedKeyType object or NULL
*/
struct xenc__EncryptedKeyType*
soap_wsse_EncryptedKey(struct soap *soap)
{ _wsse__Security *security = soap_wsse_Security(soap);
  if (security)
    return security->xenc__EncryptedKey;
  return NULL;
}

/******************************************************************************\
 *
 * wsse:Security/xenc:EncryptedKey/ReferenceList/DataReference
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_EncryptedKey_DataReferenceURI(struct soap *soap, const char *URI)
@brief Adds a DataReference URI to the EncryptedKey header element.
@param soap context
@param[in] URI value of the URI ID
@return SOAP_OK or error code
*/
int
soap_wsse_add_EncryptedKey_DataReferenceURI(struct soap *soap, const char *URI)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  _xenc__ReferenceList *ref;
  int k, n = 0;
  DBGFUN1("soap_wsse_add_EncryptedKey_DataReferenceURI", "URI=%s", URI?URI:"");
  if (!security->xenc__EncryptedKey)
  { if (!(security->xenc__EncryptedKey = (xenc__EncryptedKeyType*)soap_malloc(soap, sizeof(xenc__EncryptedKeyType))))
      return soap->error = SOAP_EOM;
    soap_default_xenc__EncryptedKeyType(soap, security->xenc__EncryptedKey); 
  }
  if (!security->xenc__EncryptedKey->ReferenceList)
  { if (!(security->xenc__EncryptedKey->ReferenceList = (struct _xenc__ReferenceList*)soap_malloc(soap, sizeof(struct _xenc__ReferenceList))))
      return soap->error = SOAP_EOM;
    soap_default__xenc__ReferenceList(soap, security->xenc__EncryptedKey->ReferenceList);
  }
  ref = security->xenc__EncryptedKey->ReferenceList;
  k = ref->__size_ReferenceList++;
  /* need to increase space? */
  if (k < 0)
    return soap->error = SOAP_EOM;
  if (k == 0)
    n = 1;
  else if (k >= 1 && (k & (k - 1)) == 0)
    n = 2 * k;
  /* yes we do */
  if (n)
  { struct __xenc__union_ReferenceList *tmp = (struct __xenc__union_ReferenceList*)soap_malloc(soap, n * sizeof(struct __xenc__union_ReferenceList));
    int i;
    if (!tmp)
      return soap->error = SOAP_EOM;
    for (i = 0; i < k; i++)
      tmp[i] = ref->__union_ReferenceList[i];
    security->xenc__EncryptedKey->ReferenceList->__union_ReferenceList = tmp;
    ref = security->xenc__EncryptedKey->ReferenceList;
  }
  /* add entry */
  soap_default___xenc__union_ReferenceList(soap, &ref->__union_ReferenceList[k]);
  if (!(ref->__union_ReferenceList[k].DataReference = (struct xenc__ReferenceType*)soap_malloc(soap, sizeof(struct xenc__ReferenceType))))
    return soap->error = SOAP_EOM;
  soap_default_xenc__ReferenceType(soap, ref->__union_ReferenceList[k].DataReference);
  ref->__union_ReferenceList[k].DataReference->URI = soap_strdup(soap, URI);
  return SOAP_OK;
}

/**
@fn int soap_wsse_add_DataReferenceURI(struct soap *soap, const char *URI)
@brief Adds a DataReference URI to the WS-Security header element.
@param soap context
@param[in] URI value of the URI ID
@return SOAP_OK or error code
*/
int
soap_wsse_add_DataReferenceURI(struct soap *soap, const char *URI)
{ _wsse__Security *security = soap_wsse_add_Security(soap);
  _xenc__ReferenceList *ref;
  int k, n = 0;
  DBGFUN1("soap_wsse_add_DataReferenceURI", "URI=%s", URI?URI:"");
  /* initial alloc */
  if (!security->xenc__ReferenceList)
  { if (!(security->xenc__ReferenceList = (struct _xenc__ReferenceList*)soap_malloc(soap, sizeof(struct _xenc__ReferenceList))))
      return soap->error = SOAP_EOM;
    soap_default__xenc__ReferenceList(soap, security->xenc__ReferenceList);
  }
  ref = security->xenc__ReferenceList;
  k = ref->__size_ReferenceList++;
  /* need to increase space? */
  if (k < 0)
    return soap->error = SOAP_EOM;
  if (k == 0)
    n = 1;
  else if (k >= 1 && (k & (k - 1)) == 0)
    n = 2 * k;
  /* yes we do */
  if (n)
  { struct __xenc__union_ReferenceList *tmp = (struct __xenc__union_ReferenceList*)soap_malloc(soap, n * sizeof(struct __xenc__union_ReferenceList));
    int i;
    if (!tmp)
      return soap->error = SOAP_EOM;
    for (i = 0; i < k; i++)
      tmp[i] = ref->__union_ReferenceList[i];
    security->xenc__ReferenceList->__union_ReferenceList = tmp;
    ref = security->xenc__ReferenceList;
  }
  /* add entry */
  soap_default___xenc__union_ReferenceList(soap, &ref->__union_ReferenceList[k]);
  if (!(ref->__union_ReferenceList[k].DataReference = (struct xenc__ReferenceType*)soap_malloc(soap, sizeof(struct xenc__ReferenceType))))
    return soap->error = SOAP_EOM;
  soap_default_xenc__ReferenceType(soap, ref->__union_ReferenceList[k].DataReference);
  ref->__union_ReferenceList[k].DataReference->URI = soap_strdup(soap, URI);
  return SOAP_OK;
}

/******************************************************************************\
 *
 * xenc:EncryptedData
 *
\******************************************************************************/

/**
@fn int soap_wsse_add_EncryptedData_KeyInfo_KeyName(struct soap *soap, const char *keyname)
@brief Adds EncryptedData/ds:KeyInfo/Keyname elements.
@param soap context
@param[in] keyname name of the key
@return SOAP_OK or error code

This function adds the name of the key to each EncryptedData element to
identify the shared secret key used for encryption.
*/
int
soap_wsse_add_EncryptedData_KeyInfo_KeyName(struct soap *soap, const char *keyname)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_add_EncryptedData_KeyInfo_KeyName");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_add_EncryptedData_KeyInfo_KeyName", "Plugin not registered", SOAP_PLUGIN_ERROR);
  data->enco_keyname = soap_strdup(soap, keyname);
  return SOAP_OK;
}

/******************************************************************************\
 *
 * Faults
 *
\******************************************************************************/

/**
@fn int soap_wsse_sender_fault_subcode(struct soap *soap, const char *faultsubcode, const char *faultstring, const char *faultdetail)
@brief Sets sender SOAP Fault (sub)code for server fault response.
@param soap context
@param[in] faultsubcode sub code string
@param[in] faultstring fault string
@param[in] faultdetail detail string
@return SOAP_FAULT
*/
int
soap_wsse_sender_fault_subcode(struct soap *soap, const char *faultsubcode, const char *faultstring, const char *faultdetail)
{
#if defined(SOAP_WSA_2003) || defined(SOAP_WSA_2004) || defined(SOAP_WSA_200408) || defined(SOAP_WSA_2005)
  return soap_wsa_sender_fault_subcode(soap, faultsubcode, faultstring, faultdetail);
#else
  return soap_sender_fault_subcode(soap, faultsubcode, faultstring, faultdetail);
#endif
}

/**
@fn int soap_wsse_receiver_fault_subcode(struct soap *soap, const char *faultsubcode, const char *faultstring, const char *faultdetail)
@brief Sets receiver SOAP Fault (sub)code for server fault response.
@param soap context
@param[in] faultsubcode sub code string
@param[in] faultstring fault string
@param[in] faultdetail detail string
@return SOAP_FAULT
*/
int
soap_wsse_receiver_fault_subcode(struct soap *soap, const char *faultsubcode, const char *faultstring, const char *faultdetail)
{
#if defined(SOAP_WSA_2003) || defined(SOAP_WSA_2004) || defined(SOAP_WSA_200408) || defined(SOAP_WSA_2005)
  return soap_wsa_receiver_fault_subcode(soap, faultsubcode, faultstring, faultdetail);
#else
  return soap_receiver_fault_subcode(soap, faultsubcode, faultstring, faultdetail);
#endif
}

/**
@fn int soap_wsse_sender_fault(struct soap *soap, const char *faultstring, const char *faultdetail)
@brief Sets sender SOAP Fault for server fault response.
@param soap context
@param[in] faultstring fault string
@param[in] faultdetail detail string
@return SOAP_FAULT
*/
int
soap_wsse_sender_fault(struct soap *soap, const char *faultstring, const char *faultdetail)
{ return soap_wsse_sender_fault_subcode(soap, NULL, faultstring, faultdetail);
}

/**
@fn int soap_wsse_receiver_fault(struct soap *soap, const char *faultstring, const char *faultdetail)
@brief Sets receiver SOAP Fault for server fault response.
@param soap context
@param[in] faultstring fault string
@param[in] faultdetail detail string
@return SOAP_FAULT
*/
int
soap_wsse_receiver_fault(struct soap *soap, const char *faultstring, const char *faultdetail)
{ return soap_wsse_receiver_fault_subcode(soap, NULL, faultstring, faultdetail);
}

/**
@fn int soap_wsse_fault(struct soap *soap, wsse__FaultcodeEnum fault, const char *detail)
@brief Sets SOAP Fault (sub)code for server response.
@param soap context
@param[in] fault is one of wsse:FaultcodeEnum
@param[in] detail string with optional text message
@return SOAP_FAULT
*/
int
soap_wsse_fault(struct soap *soap, wsse__FaultcodeEnum fault, const char *detail)
{ const char *code = soap_wsse__FaultcodeEnum2s(soap, fault);
  DBGFUN2("soap_wsse_fault", "fault=%s", code?code:"", "detail=%s", detail?detail:"");
  /* remove incorrect or incomplete Security header */
  soap_wsse_delete_Security(soap);
  /* populate the SOAP Fault as per WS-Security spec */
  /* detail = NULL; */ /* uncomment when detail text not recommended */
  /* use WSA to populate the SOAP Header when WSA is used */
  switch (fault)
  { case wsse__UnsupportedSecurityToken:
      return soap_wsse_sender_fault_subcode(soap, code, "An unsupported token was provided", detail);
    case wsse__UnsupportedAlgorithm:
      return soap_wsse_sender_fault_subcode(soap, code, "An unsupported signature or encryption algorithm was used", detail);
    case wsse__InvalidSecurity:
      return soap_wsse_sender_fault_subcode(soap, code, "An error was discovered processing the <wsse:Security> header", detail);
    case wsse__InvalidSecurityToken:
      return soap_wsse_sender_fault_subcode(soap, code, "An invalid security token was provided", detail);
    case wsse__FailedAuthentication:
      return soap_wsse_sender_fault_subcode(soap, code, "The security token could not be authenticated or authorized", detail);
    case wsse__FailedCheck:
      return soap_wsse_sender_fault_subcode(soap, code, "The signature or decryption was invalid", detail);
    case wsse__SecurityTokenUnavailable:
      return soap_wsse_sender_fault_subcode(soap, code, "Referenced security token could not be retrieved", detail);
  }
  return SOAP_FAULT;
}

/******************************************************************************\
 *
 * Digest authentication session management
 *
\******************************************************************************/

/**
@fn static int soap_wsse_session_verify(struct soap *soap, const char hash[SOAP_SMD_SHA1_SIZE], const char *created, const char *nonce)
@brief Verifies and updates the digest, nonce, and creation time against the digest authentication session database to prevent replay attacks.
@param soap context
@param[in] hash binary digest value of PasswordDigest
@param[in] created string
@param[in] nonce string (base64)
@return SOAP_OK or SOAP_FAULT
*/
static int
soap_wsse_session_verify(struct soap *soap, const char hash[SOAP_SMD_SHA1_SIZE], const char *created, const char *nonce)
{ struct soap_wsse_session *session;
  time_t expired, now = time(NULL);
  DBGFUN("soap_wsse_session_verify");
  soap_s2dateTime(soap, created, &expired);
  /* creation time in the future? */
  if (expired > now + SOAP_WSSE_CLKSKEW)
    return soap_wsse_fault(soap, wsse__FailedAuthentication, "Authorization request in future");
  expired += SOAP_WSSE_NONCETIME;
  /* expired? */
  if (expired <= now)
    return soap_wsse_fault(soap, wsse__FailedAuthentication, "Authentication expired");
  /* purge expired messages, but don't do this all the time to improve efficiency */
  if (now % 10 == 0)
    soap_wsse_session_cleanup(soap);
  DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Verifying session nonce=%s\n", nonce));
  /* enter mutex to check and update session */
  MUTEX_LOCK(soap_wsse_session_lock);
  for (session = soap_wsse_session; session; session = session->next)
  { if (!memcmp(session->hash, hash, SOAP_SMD_SHA1_SIZE) && !strcmp(session->nonce, nonce))
      break;
  }
  /* if not found, allocate new session data */
  if (!session)
  { session = (struct soap_wsse_session*)malloc(sizeof(struct soap_wsse_session) + strlen(nonce));
    if (session)
    { session->next = soap_wsse_session;
      session->expired = expired;
      memcpy(session->hash, hash, SOAP_SMD_SHA1_SIZE);
      strcpy(session->nonce, nonce);
      soap_wsse_session = session;
    }
    session = NULL;
  }
  /* exit mutex */
  MUTEX_UNLOCK(soap_wsse_session_lock);
  /* if replay attack, return non-descript failure */
  if (session)
    return soap_wsse_fault(soap, wsse__FailedAuthentication, NULL);
  return SOAP_OK;
}

/**
@fn static void soap_wsse_session_cleanup(struct soap *soap)
@brief Removes expired authentication data from the digest authentication session database.
@param soap context
*/
static void
soap_wsse_session_cleanup(struct soap *soap)
{ struct soap_wsse_session **session;
  time_t now = time(NULL);
  DBGFUN("soap_wsse_session_cleanup");
  /* enter mutex to purge expired session data */
  MUTEX_LOCK(soap_wsse_session_lock);
  session = &soap_wsse_session;
  while (*session)
  { if ((*session)->expired < now)
    { struct soap_wsse_session *p = *session;
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Deleting session nonce=%s\n", p->nonce));
      *session = p->next;
      free(p);
    }
    else
      session = &(*session)->next;
  }
  /* exit mutex */
  MUTEX_UNLOCK(soap_wsse_session_lock);
}

/******************************************************************************\
 *
 * Calculate SHA1(created, nonce, password) digest
 *
\******************************************************************************/

/**
@fn static void calc_digest(struct soap *soap, const char *created, const char *nonce, int noncelen, const char *password, char hash[SOAP_SMD_SHA1_SIZE])
@brief Calculates digest value SHA1(created, nonce, password)
@param soap context
@param[in] created string (XSD dateTime format)
@param[in] nonce value
@param[in] noncelen length of nonce value
@param[in] password string
@param[out] hash SHA1 digest
*/
static void
calc_digest(struct soap *soap, const char *created, const char *nonce, int noncelen, const char *password, char hash[SOAP_SMD_SHA1_SIZE])
{ struct soap_smd_data context;
  /* use smdevp engine */
  soap_smd_init(soap, &context, SOAP_SMD_DGST_SHA1, NULL, 0);
  soap_smd_update(soap, &context, nonce, noncelen);
  soap_smd_update(soap, &context, created, strlen(created));
  soap_smd_update(soap, &context, password, strlen(password));
  soap_smd_final(soap, &context, hash, NULL);
}

/******************************************************************************\
 *
 * Calculate randomized hex nonce
 *
\******************************************************************************/

/**
@fn static void calc_nonce(struct soap *soap, char nonce[SOAP_WSSE_NONCELEN])
@brief Calculates randomized nonce (also uses time() in case a poorly seeded PRNG is used)
@param soap context
@param[out] nonce value
*/
static void
calc_nonce(struct soap *soap, char nonce[SOAP_WSSE_NONCELEN])
{ int i;
  time_t r = time(NULL);
  memcpy(nonce, &r, 4);
  for (i = 4; i < SOAP_WSSE_NONCELEN; i += 4)
  { r = soap_random;
    memcpy(nonce + i, &r, 4);
  }
}

/******************************************************************************\
 *
 * Plugin registry functions
 *
\******************************************************************************/

/**
@fn int soap_wsse(struct soap *soap, struct soap_plugin *p, void *arg)
@brief Plugin registry function, used with soap_register_plugin.
@param soap context
@param[in,out] p plugin created in registry
@param[in] arg passed from soap_register_plugin_arg is an optional security token handler callback
@return SOAP_OK
*/
int
soap_wsse(struct soap *soap, struct soap_plugin *p, void *arg)
{ static int done = 0;
  DBGFUN("soap_wsse");
  p->id = soap_wsse_id;
  p->data = (void*)SOAP_MALLOC(soap, sizeof(struct soap_wsse_data));
  p->fcopy = soap_wsse_copy;
  p->fdelete = soap_wsse_delete;
  if (p->data)
  { if (soap_wsse_init(soap, (struct soap_wsse_data*)p->data, (const void *(*)(struct soap*, int*, const char*, int*))arg))
    { SOAP_FREE(soap, p->data);
      return SOAP_EOM;
    }
  }
  if (!done)
  {
#if 0
#ifdef WIN32
    /* now uses CreateMutex() for static lock initialization */
    static volatile long spinlock = 0;
    DWORD s = 0;
    /* Initialize soap_wsse_session_lock with a spinlock */
    while (InterlockedExchange(&spinlock, 1) == 1)
    { Sleep(s);
      s = !s;
    }
    if (!done)
      MUTEX_SETUP(soap_wsse_session_lock);
    done = 1;
    spinlock = 0;
#else
    done = 1;
#endif
#endif
#ifdef WITH_OPENSSL
    /* moved to stdsoap2.c
    MUTEX_LOCK(soap_wsse_session_lock);
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
    MUTEX_UNLOCK(soap_wsse_session_lock);
    */
#endif
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_init(struct soap *soap, struct soap_wsse_data *data, const void *(*arg)(struct soap*, int*, const char*, int*))
@brief Initializes plugin data.
@param soap context
@param[in,out] data plugin data
@param arg security token handler callback
@return SOAP_OK
*/
static int
soap_wsse_init(struct soap *soap, struct soap_wsse_data *data, const void *(*arg)(struct soap*, int *alg, const char *keyname, int *keylen))
{ DBGFUN("soap_wsse_init");
  data->sigid = NULL;
  data->encid = NULL;
  data->sign_alg = SOAP_SMD_NONE;
  data->sign_key = NULL;
  data->sign_keylen = 0;
  data->vrfy_alg = SOAP_SMD_NONE;
  data->vrfy_key = NULL;
  data->vrfy_keylen = 0;
  data->enco_alg = SOAP_MEC_NONE;
  data->enco_keyname = NULL;
  data->enco_key = NULL;
  data->enco_keylen = 0;
  data->deco_alg = SOAP_MEC_NONE;
  data->deco_key = NULL;
  data->deco_keylen = 0;
  data->digest = NULL;
  data->fpreparesend = NULL;
  data->fpreparefinalsend = NULL;
  data->fpreparefinalrecv = NULL;
  data->fheader = soap->fheader;
  soap->fheader = soap_wsse_header;
  data->mec = NULL;
  data->store = NULL;
  data->security_token_handler = arg;
  soap->feltbegin = soap_wsse_element_begin_in; 
  soap->feltendin = soap_wsse_element_end_in;
  return SOAP_OK;
}

/**
@fn int soap_wsse_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src)
@brief Copies plugin data to localize plugin data for threads.
@param soap context
@param[out] dst target plugin
@param[in] src source plugin
@return SOAP_OK
*/
static int
soap_wsse_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src)
{ DBGFUN("soap_wsse_copy");
  *dst = *src;
  dst->data = (void*)SOAP_MALLOC(soap, sizeof(struct soap_wsse_data));
  soap_wsse_init(soap, (struct soap_wsse_data*)dst->data, ((struct soap_wsse_data*)src->data)->security_token_handler);
  return SOAP_OK;
}

/**
@fn void soap_wsse_delete(struct soap *soap, struct soap_plugin *p)
@brief Deletes plugin data.
@param soap context
@param[in,out] p plugin
@return SOAP_OK
*/
static void
soap_wsse_delete(struct soap *soap, struct soap_plugin *p)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_delete");
  if (data)
  { soap_wsse_preparecleanup(soap, data);
    if (data->mec)
    { soap_mec_cleanup(soap, data->mec);
      SOAP_FREE(soap, data->mec);
      data->mec = NULL;
    }
    if (data->store)
    { X509_STORE_free(data->store);
      data->store = NULL;
    }
    SOAP_FREE(soap, data);
  }
}

/******************************************************************************\
 *
 * Plugin-specific functions
 *
\******************************************************************************/

/**
@fn int soap_wsse_set_wsu_id(struct soap *soap, const char *tags)
@brief Sets the elements that are to be extended with wsu:Id attributes. The
wsu:Id attribute values are set to the string value of the tag's QName by
replacing colons with hyphens to produce an xsd:ID value.
@param soap context
@param[in] tags string of space-separated qualified and unqualified element tag names
@return SOAP_OK
*/
int
soap_wsse_set_wsu_id(struct soap *soap, const char *tags)
{ DBGFUN1("soap_wsse_set_wsu_id", "tags=%s", tags?tags:"(null)");
  soap->wsuid = soap_strdup(soap, tags);
  return SOAP_OK;
}

/**
@fn int soap_wsse_sign_only(struct soap *soap, const char *tags)
@brief Filters only the specified wsu:Id names for signing. Can be used with soap_wsse_set_wsu_id() and if so should use the element tag names.
@param soap context
@param[in] tags string of space-separated qualified and unqualified tag names
@return SOAP_OK
*/
int
soap_wsse_sign_only(struct soap *soap, const char *tags)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN1("soap_wsse_sign_only", "tags=%s", tags?tags:"(null)");
  if (data)
    data->sigid = soap_wsse_ids(soap, tags);
  return SOAP_OK;
}

/**
@fn static char* soap_wsse_ids(struct soap *soap, const char *tags)
@brief converts tag name(s) to id name(s)
@param soap context
@param[in] tags string of space-separated (un)qualified tag names
@return string of ids
*/
static char*
soap_wsse_ids(struct soap *soap, const char *tags)
{ char *s, *t;
  s = t = soap_strdup(soap, tags);
  while (s && *s)
  { if (*s == ':')
      *s = '-';
    s++;
  }
  return t;
}

/**
@fn int soap_wsse_sign(struct soap *soap, int alg, const void *key, int keylen)
@brief Uses the wsse plugin to sign all wsu:Id attributed elements.
@param soap context
@param[in] alg is the signature algorithm, such as SOAP_SMD_HMAC_SHA1, SOAP_SMD_SIGN_DSA_SHA1, or SOAP_SMD_SIGN_RSA_SHA1
@param[in] key is the HMAC secret key or DSA/RSA private EVP_PKEY
@param[in] keylen is the HMAC key length
@return SOAP_OK or fault

This function does not actually sign the message, but initiates the plugin's
signature algorithm to sign the message upon message transfer.
*/
int
soap_wsse_sign(struct soap *soap, int alg, const void *key, int keylen)
{ struct soap_wsse_digest *digest, *next;
  struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN1("soap_wsse_sign", "alg=%x", alg);
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_sign", "Plugin not registered", SOAP_PLUGIN_ERROR);
  if (!alg || !key)
    return soap_wsse_fault(soap, wsse__InvalidSecurity, "Invalid signature algorithm or key");
  /* store alg and key in plugin data */
  data->sign_alg = alg;
  data->sign_key = key;
  data->sign_keylen = keylen;
  /* save and set the plugin's callbacks to preprocess outbound messages */
  if (soap->fpreparesend != soap_wsse_preparesend)
  { data->fpreparesend = soap->fpreparesend;
    data->fpreparefinalsend = soap->fpreparefinalsend;
  }
  if (soap->fpreparefinalsend != soap_wsse_preparefinalsend)
  { soap->fpreparesend = soap_wsse_preparesend;
    soap->fpreparefinalsend = soap_wsse_preparefinalsend;
  }
  /* support HTTP compression only with HTTP chunking to allow signing XML */
  if ((soap->omode & SOAP_ENC_ZLIB))
    soap->omode = (soap->omode & ~SOAP_IO) | SOAP_IO_CHUNK;
  else if ((soap->omode & SOAP_IO) == SOAP_IO_STORE) /* no store buffering */
    soap->omode = (soap->omode & ~SOAP_IO) | SOAP_IO_BUFFER;
  /* cleanup the digest data */
  for (digest = data->digest; digest; digest = next)
  { next = digest->next;
    SOAP_FREE(soap, digest);
  }
  data->digest = NULL;
  return SOAP_OK;
}

/**
@fn int soap_wsse_sign_body(struct soap *soap, int alg, const void *key, int keylen)
@brief Uses the wsse plugin to sign all wsu:Id attributed elements, including the SOAP Body (by adding a wsu:Id="Body" attribute).
@param soap context
@param[in] alg is the signature algorithm, such as SOAP_SMD_HMAC_SHA1, SOAP_SMD_SIGN_DSA_SHA1, or SOAP_SMD_SIGN_RSA_SHA1
@param[in] key is the HMAC secret key or DSA/RSA private EVP_PKEY
@param[in] keylen is the HMAC key length
@return SOAP_OK

This function does not actually sign the message, but initiates the plugin's
signature algorithm to sign the message upon message transfer.
*/
int
soap_wsse_sign_body(struct soap *soap, int alg, const void *key, int keylen)
{ DBGFUN1("soap_wsse_sign_body", "alg=%x", alg);
  soap_wsse_add_Security(soap);
  soap->omode |= SOAP_SEC_WSUID;
  return soap_wsse_sign(soap, alg, key, keylen);
}

/**
@fn int soap_wsse_verify_init(struct soap *soap)
@brief Uses the wsse plugin to initiate the verification of the signature and SignedInfo Reference digests.
@param soap context
@return SOAP_OK

This function does not actually verify the message, but initiates the plugin's
data to store the message in a DOM to verify the signature. The signature and
digests in the DOM must be verified manually.
*/
int
soap_wsse_verify_init(struct soap *soap)
{ DBGFUN("soap_wsse_verify_init");
  /* deserialize inbound message to DOM */
  soap->imode |= SOAP_XML_DOM;
  return SOAP_OK;
}

/**
@fn int soap_wsse_verify_auto(struct soap *soap, int alg, const void *key, size_t keylen)
@brief Uses the wsse plugin to initiate the automatic verification of the signature and SignedInfo Reference digests.
@param soap context
@param[in] alg to verify signature if signature has no secret or public key, use SOAP_SMD_NONE to omit
@param[in] key is HMAC key or EVP_PKEY or NULL
@param[in] keylen is HMAC key length or 0
@return SOAP_OK

This function does not actually verify the message, but initiates the plugin's
algorithm to store the message in a DOM to automatically verify the signature
and digests. If the message does not contain a key to verify the signature,
the alg, key, and keylen parameters are used. It is important that the X509
certificate used to verify the signature, which requires soap->cafile and/or
soap->capath to be set.
*/
int
soap_wsse_verify_auto(struct soap *soap, int alg, const void *key, size_t keylen)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_verify_auto");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_verify_auto", "Plugin not registered", SOAP_PLUGIN_ERROR);
  data->vrfy_alg = alg;
  data->vrfy_key = key;
  data->vrfy_keylen = keylen;
  if (soap->fpreparefinalrecv != soap_wsse_preparefinalrecv)
  { data->fpreparefinalrecv = soap->fpreparefinalrecv;
    soap->fpreparefinalrecv = soap_wsse_preparefinalrecv; 
  }
  return soap_wsse_verify_init(soap);
}

/**
@fn int soap_wsse_verify_done(struct soap *soap)
@brief Terminates the automatic verification of signatures.
@param soap context
@return SOAP_OK
*/
int
soap_wsse_verify_done(struct soap *soap)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_verify_done");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_verify_done", "Plugin not registered", SOAP_PLUGIN_ERROR);
  soap->imode &= ~SOAP_XML_DOM;
  soap->omode &= ~SOAP_SEC_WSUID;
  if (soap->fpreparefinalrecv == soap_wsse_preparefinalrecv)
    soap->fpreparefinalrecv = data->fpreparefinalrecv;
  return SOAP_OK;
}

/**
@fn size_t soap_wsse_verify_element(struct soap *soap, const char *URI, const char *tag)
@brief Post-checks the presence of signed element(s). Does not verify the
signature of these elements, which is done with @ref soap_wsse_verify_auto.
@param soap context
@param URI namespace of element(s)
@param tag name of element(s)
@return number of matching elements signed.

This function does not actually verify the signature of each element, but
checks whether the elements are signed and thus their integrity is preserved.
Signed element nesting rules are obeyed, so if the matching element is a
descendent of a signed element, it is signed as well.  Thus, the verification
process follows nesting rules.

Client should call this function after invocation. Services should call this
function inside a service operation. This function traverses the entire DOM, so
performance is determined by the size of a message.

To check the SOAP Body (either using SOAP 1.1 or 1.2), @ref soap_wsse_verify_element(soap, namespaces[0].ns, "Body"). To check whether the Timestamp was signed (assuming it is present and message expiration checked with @ref soap_wsse_verify_Timestamp), use @ref soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp").

Note: for future releases XPath queries (or forms of these) will be considered.
*/
size_t
soap_wsse_verify_element(struct soap *soap, const char *URI, const char *tag)
{ ds__SignedInfoType *signedInfo = soap_wsse_SignedInfo(soap);
  size_t count = 0;
  DBGFUN("soap_wsse_verify_element");
  if (signedInfo && soap->dom)
  { struct soap_dom_element *elt;
    /* traverse the DOM */
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "SignedInfo and DOM found\n"));
    elt = soap->dom;
    while (elt)
    { /* find wsu:Id or ds:Id and check for Id in signedInfo */
      int ok = 0;
      struct soap_dom_attribute *att;
      for (att = elt->atts; att; att = att->next)
      { if (att->name
         && att->nstr
         && (!strcmp(att->nstr, wsu_URI) || !strcmp(att->nstr, ds_URI))
         && (!strcmp(att->name, "Id") || !soap_tag_cmp(att->name, "*:Id")))
        { /* Id attribute found, search Id value in ds:Reference/@URI */
          int i;
          for (i = 0; i < signedInfo->__sizeReference; i++)
          { ds__ReferenceType *reference = signedInfo->Reference[i];
            if (reference->URI && *reference->URI == '#' && !strcmp(reference->URI + 1, att->data))
            { ok = 1;
              break;
            }
          }
	  if (ok)
            break;
        }
      }
      /* the current element is signed, count this and the matching nested */
      if (ok)
      { count += soap_wsse_verify_nested(soap, elt, URI, tag);
	/* go to next sibling or back up */
        if (elt->next)
	  elt = elt->next;
	else
	{ do elt = elt->prnt;
	  while (elt && !elt->next);
	  if (elt)
	    elt = elt->next;
	}
      }
      else
        elt = soap_dom_next_element(elt);
    }
  }
  return count;
}

/**
@fn size_t soap_wsse_verify_nested(struct soap *soap, struct soap_dom_element *dom, const char *URI, const char *tag)
@brief Counts signed matching elements from the dom node and down
@param soap context
@param dom node to check and down
@param URI namespace of element(s)
@param tag name of element(s)
@return number of matching elements.
*/
static size_t
soap_wsse_verify_nested(struct soap *soap, struct soap_dom_element *dom, const char *URI, const char *tag)
{ size_t count = 0;
  /* search the DOM node and descendants for matching elements */
  struct soap_dom_element *elt = dom;
  for (elt = dom; elt && elt != dom->next && elt != dom->prnt; elt = soap_dom_next_element(elt))
  { if (elt->name && ((!elt->nstr && !URI) || (elt->nstr && URI && !strcmp(elt->nstr, URI))))
    { const char *s = strchr(elt->name, ':');
      if (s)
        s++;
      else
        s = elt->name;
      /* found element? */
      if (!strcmp(s, tag))
        count++;
    }
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Element '%s' (\"%s\":%s) is signed\n", elt->name, elt->nstr, elt->name));
  }
  return count;
}

/**
@fn int soap_wsse_verify_body(struct soap *soap)
@brief Post-checks the presence of signed SOAP Body. Does not verify the
signature of the Body, which is done with @ref soap_wsse_verify_auto.
@param soap context
@return SOAP_OK (signed) or SOAP_FAULT

This function does not actually verify the signature of the Body. It checks
whether the Body is signed and thus its integrity is preserved. Clients should
call this function after invocation. Services should call this function inside
a service operation. This function traverses the entire DOM, so performance is
determined by the size of a message.
*/
int
soap_wsse_verify_body(struct soap *soap)
{ const char *ns = NULL;
  /* Are we using SOAP 1.1 or 1.2? Check first row of namespace table */
  if (soap->local_namespaces)
  { if (soap->local_namespaces->out)
      ns = soap->local_namespaces->out;
    else if (soap->local_namespaces->ns)
      ns = soap->local_namespaces->ns;
  }
  /* We don't know if we're using SOAP 1.1 or 1.2, so assume it is 1.2 */
  if (!ns)
    ns = "http://www.w3.org/2003/05/soap-envelope";
  if (soap_wsse_verify_element(soap, ns, "Body") > 0)
    return SOAP_OK;
  return soap_wsse_sender_fault(soap, "Message body not signed", NULL);
}

/**
@fn int soap_wsse_encrypt_body(struct soap *soap, int alg, const void *key, int keylen)
@brief Initiates the encryption of the SOAP Body. The algorithm should be
SOAP_MEC_ENC_DES_CBC or one of SOAP_MEC_ENC_AESxxx_CBC for symmetric
encryption. Use soap_wsse_add_EncryptedKey for public key encryption.
@param soap context
@param[in] alg the encryption algorithm, should be SOAP_MEC_ENC_DES_CBC or one
of SOAP_MEC_ENC_AESxxx_CBC
@param[in] key a certificate with public key for encryption, a DES CBC 160-bit key or AES key
@param[in] keylen the symmetric encryption key length, 20 bytes for a DES CBC 160-bit key
@return SOAP_OK or error code

This function initiates the encryption of the SOAP Body using an RSA public key
or a symmetric shared secret key. No WS-Security EncryptedKey header will be
set. Use soap_wsse_add_EncryptedKey instead for public key encryption.
*/
int
soap_wsse_encrypt_body(struct soap *soap, int alg, const void *key, int keylen)
{ struct soap_wsse_data *data;
  DBGFUN1("soap_wsse_encrypt_body", "alg=%x", alg);
  data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_encrypt_body", "Plugin not registered", SOAP_PLUGIN_ERROR);
  data->encid = NULL;
  soap->omode |= SOAP_SEC_WSUID;
  soap_wsse_add_DataReferenceURI(soap, "#Body");
  return soap_wsse_encrypt(soap, alg, key, keylen);
}

/**
@fn int soap_wsse_encrypt_only(struct soap *soap, int alg, const void *key, int keylen, const char *tags)
@brief Initiates the encryption of XML elements specified in the tags string.
Should be used in combination with soap_wsse_set_wsu_id to set wsu:Id for given
XML element tags. The algorithm should be SOAP_MEC_ENC_DES_CBC or one of
SOAP_MEC_ENC_AESxxx_CBC for symmetric encryption. Use
soap_wsse_add_EncryptedKey_encrypt_only for public key encryption.
@param soap context
@param[in] alg the encryption algorithm, should be SOAP_MEC_ENC_DES_CBC or one
of SOAP_MEC_ENC_AESxxx_CBC
@param[in] key a certificate with public key for encryption, a DES CBC 160-bit key or AES key
@param[in] keylen the symmetric encryption key length, 20 bytes for a DES CBC 160-bit key
@param[in] tags string of space-separated qualified and unqualified tag names
@return SOAP_OK or error code

This function initiates the encryption using an RSA public key or a symmetric
shared secret key. No WS-Security EncryptedKey header will be set. Use
soap_wsse_add_EncryptedKey instead for public key encryption.

WARNING:
Use @ref soap_wsse_add_EncryptedKey_encrypt_only only in combination with
@ref soap_wsse_set_wsu_id with the tag names of the elements to be encrypted.
OTHERWISE THE GIVEN XML ELEMENTS ARE NOT ENCRYPTED AND WILL BE SENT IN THE
CLEAR.

WARNING:
The elements identified with @ref soap_wsse_set_wsu_id to encrypt MUST occur
EXACTLY ONCE in the SOAP Body.

WARNING:
Encryption/decryption of elements with simple content (CDATA content) IS NOT
SUPPORTED. This means that elements you want to encrypt with this function must
have complex content. That is, only encrypt elements with sub elements or
encrypt the entire SOAP Body.
*/
int
soap_wsse_encrypt_only(struct soap *soap, int alg, const void *key, int keylen, const char *tags)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN2("soap_wsse_encrypt_only", "alg=%x", alg, "tags=%s", tags?tags:"(null)");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_encrypt_only", "Plugin not registered", SOAP_PLUGIN_ERROR);
  data->encid = soap_strdup(soap, tags);
  if (tags)
  { char *s, *t;
    /* make space to insert # to each id converted from a tag name */
    t = (char*)soap_malloc(soap, strlen(tags) + 2);
    if (!t)
      return soap->error = SOAP_EOM;
    *t = '#';
    strcpy(t + 1, tags);
    s = soap_wsse_ids(soap, t);
    if (!s)
      return soap->error = SOAP_EOM;
    s++;
    do
    { t = strchr(s, ' ');
      if (t)
        *t = '\0';
      s--;
      *s = '#';
      if (soap_wsse_add_DataReferenceURI(soap, s))
        return soap->error;
      s = t;
      while (s && *s == ' ')
        s++;
    } while (s);
  }
  return soap_wsse_encrypt(soap, alg, key, keylen);
}

/**
@fn int soap_wsse_encrypt(struct soap *soap, int alg, const void *key, int keylen)
@brief Start encryption. This function is supposed to be used internally only.
The algorithm should be SOAP_MEC_ENC_DES_CBC or one of SOAP_MEC_ENC_AESxxx_CBC
for symmetric encryption. Use soap_wsse_add_EncryptedKey for public key
encryption.
@param soap context
@param[in] alg the encryption algorithm, should be SOAP_MEC_ENC_DES_CBC or one
of SOAP_MEC_ENC_AESxxx_CBC
@param[in] key a certificate with public key for encryption, a DES CBC 160-bit key or AES key
@param[in] keylen the symmetric encryption key length, 20 bytes for a DES CBC 160-bit key
@return SOAP_OK or error code
*/
int
soap_wsse_encrypt(struct soap *soap, int alg, const void *key, int keylen)
{ struct soap_wsse_data *data;
  DBGFUN1("soap_wsse_encrypt", "alg=%x", alg);
  data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_encrypt", "Plugin not registered", SOAP_PLUGIN_ERROR);
  if (!alg || !key)
    return soap_wsse_fault(soap, wsse__UnsupportedAlgorithm, "An unsupported signature or encryption algorithm was used");
  if (alg & SOAP_MEC_ENV)
    return soap_wsse_add_EncryptedKey(soap, alg, NULL, (X509*)key, NULL, NULL, NULL);
  /* store alg and key in plugin data */
  data->enco_alg = (alg | SOAP_MEC_ENC);
  data->enco_key = key;
  data->enco_keylen = keylen;
  if (data->mec)
    soap_mec_cleanup(soap, data->mec);
  else
    data->mec = (struct soap_mec_data*)SOAP_MALLOC(soap, sizeof(struct soap_mec_data));
  if (soap_mec_begin(soap, data->mec, alg, NULL, (unsigned char*)key, &keylen))
    return soap->error;
  soap->feltbegout = soap_wsse_element_begin_out;
  soap->feltendout = soap_wsse_element_end_out;
  return SOAP_OK;
}

/**
@fn int soap_wsse_decrypt_auto(struct soap *soap, int alg, const void *key, int keylen)
@brief Start automatic decryption when needed using the specified key. This
function should be used just once. The algorithm should be
SOAP_MEC_ENV_DEC_DES_CBC for public key encryption/decryption and
SOAP_MEC_DEC_DES_CBC for symmetric shared secret keys.
@param soap context
@param[in] alg the decryption algorithm, 
@param[in] key a persistent decryption key for the algorithm, a private RSA key or a shared symmetric secret key
@param[in] keylen use 0 for public-key encryption/decryption
or the shared secret decryption key length, 20 bytes for a DES CBC 160-bit key
@return SOAP_OK or error code

This function can be called once before multiple messages are received with
WS-Security encrypted content, where only one key is used for encryption
(public key or shared secret key). The default decryption key is set. If
multiple decryption keys should be used, do NOT use this function but set the
security_token_handler callback of the wsse plugin. See @ref wsse_9_2. Use a
NULL key to remove the default decryption key.
*/
int
soap_wsse_decrypt_auto(struct soap *soap, int alg, const void *key, int keylen)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN1("soap_wsse_decrypt_auto", "alg=%x", alg);
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_decrypt_auto", "Plugin not registered", SOAP_PLUGIN_ERROR);
  /* store alg and key in plugin data */
  data->deco_alg = (alg & ~SOAP_MEC_ENC);
  /* TODO add? data->enco_alg = (alg & ~(SOAP_MEC_ENC|SOAP_MEC_ENV)); */
  data->deco_key = key;
  data->deco_keylen = keylen;
  return SOAP_OK;
}

/**
@fn int soap_wsse_encrypt_begin(struct soap *soap, const char *id, int alg, const char *URI, const char *keyname, const unsigned char *key)
@brief Emit XML encryption tags and start encryption of the XML element content.
@param soap context
@param[in] id string for the EncryptedData element Id attribute
@param[in] alg algorithm used, or SOAP_MEC_NONE to ignore
@param[in] URI string for the encrypted element wsu:Id attribute
@param[in] keyname optional subject key name
@param[in] key optional DES/AES key for encryption (to override the current key)
@return SOAP_OK or error code
*/
int
soap_wsse_encrypt_begin(struct soap *soap, const char *id, int alg, const char *URI, const char *keyname, const unsigned char *key)
{ int event;
  const char *algURI = NULL;
  DBGFUN("soap_wsse_encrypt_begin");
  if ((soap->mode & SOAP_IO_LENGTH) && (soap->mode & SOAP_IO) == SOAP_IO_CHUNK)
    return SOAP_OK;
  /* disable digest */
  event = soap->event;
  soap->event = 0;
  if (soap_set_attr(soap, "Id", id, 1)
   || soap_set_attr(soap, "Type", xenc_contentURI, 1)
   || soap_element(soap, "xenc:EncryptedData", 0, NULL)
   || soap_element_start_end_out(soap, NULL))
    return soap->error;
  switch (alg & SOAP_MEC_MASK & ~SOAP_MEC_ENV)
  { case SOAP_MEC_ENC_DES_CBC:
      algURI = xenc_3desURI;
      break;
    case SOAP_MEC_ENC_AES128_CBC:
      algURI = xenc_aes128URI;
      break;
    case SOAP_MEC_ENC_AES192_CBC:
      algURI = xenc_aes192URI;
      break;
    case SOAP_MEC_ENC_AES256_CBC:
      algURI = xenc_aes256URI;
      break;
    case SOAP_MEC_ENC_AES512_CBC:
      algURI = xenc_aes512URI;
      break;
  }
  if (algURI)
  { if (soap_set_attr(soap, "Algorithm", algURI, 1)
     || soap_element(soap, "xenc:EncryptionMethod", 0, NULL)
     || soap_element_start_end_out(soap, "xenc:EncryptionMethod"))
      return soap->error;
  }
  if (URI)
  { if (soap_element(soap, "ds:KeyInfo", 0, NULL)
     || soap_element_start_end_out(soap, NULL)
     || soap_element(soap, "wsse:SecurityTokenReference", 0, NULL)
     || soap_element_start_end_out(soap, NULL)
     || soap_set_attr(soap, "URI", URI, 1)
     || soap_element(soap, "wsse:Reference", 0, NULL)
     || soap_element_start_end_out(soap, NULL)
     || soap_element_end_out(soap, "wsse:Reference")
     || soap_element_end_out(soap, "wsse:SecurityTokenReference")
     || soap_element_end_out(soap, "ds:KeyInfo"))
      return soap->error;
  }
  else if (keyname)
  { if (soap_element(soap, "ds:KeyInfo", 0, NULL)
     || soap_element_start_end_out(soap, NULL)
     || soap_element(soap, "ds:KeyName", 0, NULL)
     || soap_element_start_end_out(soap, NULL)
     || soap_string_out(soap, keyname, 0)
     || soap_element_end_out(soap, "ds:KeyName")
     || soap_element_end_out(soap, "ds:KeyInfo"))
      return soap->error;
  }
  if (soap_element(soap, "xenc:CipherData", 0, NULL)
   || soap_element_start_end_out(soap, NULL)
   || soap_element(soap, "xenc:CipherValue", 0, NULL)
   || soap_element_start_end_out(soap, NULL))
    return soap->error;
  /* re-enable digest */
  soap->event = event;
  /* adjust level, hiding xenc elements */
  soap->level -= 3;
  return soap_mec_start(soap, key);
}

/**
@fn int soap_wsse_encrypt_end(struct soap *soap)
@brief Emit XML encryption end tags and stop encryption of the XML element content.
@param soap context
@return SOAP_OK or error code
*/
int
soap_wsse_encrypt_end(struct soap *soap)
{ int event;
  DBGFUN("soap_wsse_encrypt_end");
  if ((soap->mode & SOAP_IO_LENGTH) && (soap->mode & SOAP_IO) == SOAP_IO_CHUNK)
    return SOAP_OK;
  /* disable digest */
  event = soap->event;
  soap->event = 0;
  /* adjust level, hiding xenc elements */
  soap->level += 3;
  if (soap_mec_stop(soap)
   || soap_element_end_out(soap, "xenc:CipherValue")
   || soap_element_end_out(soap, "xenc:CipherData")
   || soap_element_end_out(soap, "xenc:EncryptedData"))
    return soap->error;
  /* re-enable digest */
  soap->event = event;
  return SOAP_OK;
}

/**
@fn int soap_wsse_decrypt_begin(struct soap *soap, const unsigned char *key)
@brief Check for XML encryption tags and start decryption of the XML element
content. If the KeyInfo element is present, the security_token_handler callback
will be used to obtain a decryption key based on the key name. Otherwise the
current decryption key will be used.
@param soap context
@param[in] key optional triple DES key for decryption (to override the current key)
@return SOAP_OK or error code
*/
int
soap_wsse_decrypt_begin(struct soap *soap, const unsigned char *key)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  struct ds__KeyInfoType info;
  struct xenc__EncryptionMethodType meth;
  int alg;
  int keylen;
  DBGFUN("soap_wsse_decrypt_begin");
  if (!data)
    return soap_set_receiver_error(soap, "soap_wsse_decrypt_begin", "Plugin not registered", SOAP_PLUGIN_ERROR);
  if (soap_wsse_verify_EncryptedKey(soap))
    return soap->error;
  alg = data->deco_alg;
  keylen = data->deco_keylen;
  if (soap_element_begin_in(soap, "xenc:EncryptedData", 0, NULL))
    return soap->error;
  /* TODO: use Type attribute */
  soap_default_xenc__EncryptionMethodType(soap, &meth);
  if (soap_in_xenc__EncryptionMethodType(soap, "xenc:EncryptionMethod", &meth, NULL))
  { if (meth.Algorithm)
    { if (!strcmp(meth.Algorithm, xenc_3desURI))
        alg = (alg & (~SOAP_MEC_MASK | SOAP_MEC_ENV)) | SOAP_MEC_DEC_DES_CBC;
      else if (!strcmp(meth.Algorithm, xenc_aes128URI))
        alg = (alg & (~SOAP_MEC_MASK | SOAP_MEC_ENV)) | SOAP_MEC_DEC_AES128_CBC;
      else if (!strcmp(meth.Algorithm, xenc_aes192URI))
        alg = (alg & (~SOAP_MEC_MASK | SOAP_MEC_ENV)) | SOAP_MEC_DEC_AES192_CBC;
      else if (!strcmp(meth.Algorithm, xenc_aes256URI))
        alg = (alg & (~SOAP_MEC_MASK | SOAP_MEC_ENV)) | SOAP_MEC_DEC_AES256_CBC;
      else if (!strcmp(meth.Algorithm, xenc_aes512URI))
        alg = (alg & (~SOAP_MEC_MASK | SOAP_MEC_ENV)) | SOAP_MEC_DEC_AES512_CBC;
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "EncryptionMethod alg=%x\n", alg));
    }
  }
  if (soap_in_ds__KeyInfoType(soap, "ds:KeyInfo", &info, NULL))
  { if (data->security_token_handler && info.KeyName)
    { /* retrieve key from token handler callback */
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Getting shared secret key '%s' through security_token_handler callback\n", info.KeyName));
      key = (const unsigned char*)data->security_token_handler(soap, &alg, info.KeyName, &keylen);
    }
  }
  if (soap_element_begin_in(soap, "xenc:CipherData", 0, NULL)
   || soap_element_begin_in(soap, "xenc:CipherValue", 0, NULL))
    return soap->error;
  /* if non-envelope decryption and default secret key is set, use it */
  if (!(alg & SOAP_MEC_ENV))
  { if (alg != data->deco_alg)
    { if (data->security_token_handler)
      { /* retrieve key from token handler callback */
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Getting shared secret key for alg=%x through security_token_handler callback\n", alg));
        data->deco_key = (const unsigned char*)data->security_token_handler(soap, &alg, NULL, &keylen);
      }
    }
    if (!key)
      key = (const unsigned char*)data->deco_key;
    if (key)
    { if (data->mec)
        soap_mec_cleanup(soap, data->mec);
      else
        data->mec = (struct soap_mec_data*)SOAP_MALLOC(soap, sizeof(struct soap_mec_data));
      if (soap_mec_begin(soap, data->mec, alg, NULL, (unsigned char*)key, &keylen))
        return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
    }
  }
  data->deco_alg = alg;
  data->deco_keylen = keylen;
  if (soap_mec_start_alg(soap, alg, key))
    return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
  return SOAP_OK;
}

/**
@fn int soap_wsse_decrypt_end(struct soap *soap)
@brief Check for XML encryption ending tags and stop decryption of the XML
element content.
@param soap context
@return SOAP_OK or error code
*/
int
soap_wsse_decrypt_end(struct soap *soap)
{ DBGFUN("soap_wsse_decrypt_end");
  if (soap_mec_stop(soap)
   || soap_element_end_in(soap, "xenc:CipherValue")
   || soap_element_end_in(soap, "xenc:CipherData")
   || soap_element_end_in(soap, "xenc:EncryptedData"))
    return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
  return SOAP_OK;
}

/******************************************************************************\
 *
 * Callbacks registered by plugin
 *
\******************************************************************************/

/**
@fn int soap_wsse_header(struct soap *soap)
@brief This callback is invoked as soon as the SOAP Header is received, we need
to obtain the encrypted key when the message is encrypted to start decryption.
@param soap context
@return SOAP_OK or error code
*/
static int
soap_wsse_header(struct soap *soap)
{ /* look for encrypted elements in Body */
  /* soap->feltbegin = soap_wsse_element_begin_in; Moved, now always set */
  /* soap->feltendin = soap_wsse_element_end_in; Moved, now always set */
  /* get the encrypted key, if present */
  return soap_wsse_verify_EncryptedKey(soap);
}

/**
@fn int soap_wsse_element_begin_in(struct soap *soap, const char *tag)
@brief This callback is invoked as soon as a starting tag of an element is
received by the XML parser.
@param soap context
@param[in] tag name of the element parsed
@return SOAP_OK or error code
*/
static int
soap_wsse_element_begin_in(struct soap *soap, const char *tag)
{ /* make sure we always have a header allocated */
  if (soap->part == SOAP_IN_ENVELOPE)
    soap_header(soap);
  if (!soap_match_tag(soap, tag, "xenc:EncryptedData"))
  { struct soap_dom_element *dom = soap->dom;
    /* disable DOM */
    soap->dom = NULL;
    /* parse encryption tags */
    if (soap_wsse_decrypt_begin(soap, NULL))
      return soap->error;
    /* adjust DOM tree to skip encryption elements */
    soap->dom = dom->prnt;
    soap->dom->elts = NULL;
    /* adjust nesting level */
    soap->level -= 3;
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Decryption started, parsing decrypted XML\n"));
    soap->event = SOAP_SEC_DECRYPT;
    return soap_peek_element(soap);
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_element_end_in(struct soap *soap, const char *tag1, const char *tag2)
@brief This callback is invoked as soon as an ending tag of an element is
received by the XML parser.
@param soap context
@param[in] tag1 name of the element parsed
@param[in] tag2 name of the element that was expected by the parser's state, or NULL
@return SOAP_OK or error code
*/
static int
soap_wsse_element_end_in(struct soap *soap, const char *tag1, const char *tag2)
{ if (soap->event == SOAP_SEC_DECRYPT
   && soap->dom
   && soap->dom->elts
   && !soap_match_tag(soap, tag1, ":CipherValue"))
  { struct soap_dom_element *dom = soap->dom->elts;
    soap->event = 0;
    /* disable DOM */
    soap->dom = NULL;
    /* adjust nesting level */
    soap->level += 3;
    /* parse ending tags */
    if (soap_mec_stop(soap)
     || soap_element_end_in(soap, ":CipherData")
     || soap_element_end_in(soap, ":EncryptedData"))
      return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
    /* adjust DOM tree to skip encryption elements */
    while (dom->next)
      dom = dom->next;
    soap->dom = dom;
    return soap_element_end_in(soap, tag2);
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_element_begin_out(struct soap *soap, const char *tag)
@brief This callback is invoked as soon as a starting tag of an element is
to be sent by the XML generator.
@param soap context
@param[in] tag name of the element
@return SOAP_OK or error code
*/
static int
soap_wsse_element_begin_out(struct soap *soap, const char *tag)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  if (data && !data->encid && !strcmp(tag, "SOAP-ENV:Body"))
  { _wsse__Security *security = soap_wsse_Security(soap);
    char *URI = NULL;
    if (security && security->xenc__EncryptedKey && security->xenc__EncryptedKey->Id)
    { const char *Id = security->xenc__EncryptedKey->Id;
      if (!(URI = (char*)soap_malloc(soap, strlen(Id) + 1)))
        return soap->error = SOAP_EOM;
      *URI = '#';
      strcpy(URI + 1, Id);
    }
    /* this only encrypts the Body, so stop the callback */
    if (!(soap->mode & SOAP_IO_LENGTH))
      soap->feltbegout = NULL;
    return soap_wsse_encrypt_begin(soap, "Body", data->enco_alg, URI, data->enco_keyname, NULL);
  }
  else if (data && data->encid && soap_tagsearch(data->encid, tag))
  { _wsse__Security *security = soap_wsse_Security(soap);
    char *URI = NULL;
    if (security && security->xenc__EncryptedKey && security->xenc__EncryptedKey->Id)
    { const char *Id = security->xenc__EncryptedKey->Id;
      if (!(URI = (char*)soap_malloc(soap, strlen(Id) + 1)))
        return soap->error = SOAP_EOM;
      *URI = '#';
      strcpy(URI + 1, Id);
    }
    return soap_wsse_encrypt_begin(soap, soap_wsse_ids(soap, tag), data->enco_alg, URI, data->enco_keyname, NULL);
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_element_end_out(struct soap *soap, const char *tag)
@brief This callback is invoked as soon as an ending tag of an element is
to be sent by the XML generator.
@param soap context
@param[in] tag name of the element
@return SOAP_OK or error code
*/
static int
soap_wsse_element_end_out(struct soap *soap, const char *tag)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  if (data && !data->encid && !strcmp(tag, "SOAP-ENV:Body"))
  { if (soap_wsse_encrypt_end(soap))
      return soap->error;
    /* this version only encrypts Body, so stop the callback */
    if (!(soap->mode & SOAP_IO_LENGTH))
      soap->feltendout = NULL;
  }
  else if (data && data->encid && soap_tagsearch(data->encid, tag))
  { if (soap_wsse_encrypt_end(soap))
      return soap->error;
  }
  return SOAP_OK;
}

/**
@fn int soap_wsse_preparesend(struct soap *soap, const char *buf, size_t len)
@brief Takes a piece of the XML message (tokenized) to compute digest.
@param soap context
@param[in] buf string (XML "tokenized") to be sent
@param[in] len buf length
@return SOAP_OK or fault

This callback is invoked to analyze a message (usually during the HTTP content
length phase). Note: nested elements with wsu:Id attributes cannot be
individually signed.
*/
static int
soap_wsse_preparesend(struct soap *soap, const char *buf, size_t len)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_preparesend");
  if (!data)
    return SOAP_PLUGIN_ERROR;
  /* the gSOAP engine signals the start of a wsu:Id element */
  if (soap->event == SOAP_SEC_BEGIN)
  { int alg;
    /* start new digest or continue? */
    if (data->digest && data->digest->level)
      soap->event = SOAP_SEC_SIGN;
    else if (!data->sigid || soap_tagsearch(data->sigid, soap->id))
    { /* initialize smdevp engine */
      struct soap_wsse_digest *digest;
      soap->event = SOAP_SEC_SIGN;
      digest = (struct soap_wsse_digest*)SOAP_MALLOC(soap, sizeof(struct soap_wsse_digest) + strlen(soap->id) + 1);
      digest->next = data->digest;
      digest->level = soap->level;
      /* digest hash strength is same as signature strength */
      alg = (SOAP_SMD_DGST | (data->sign_alg & SOAP_SMD_HASH));
      soap_smd_init(soap, &digest->smd, alg, NULL, 0);
      memset(digest->hash, 0, sizeof(digest->hash));
      digest->id[0] = '#';
      strcpy(digest->id + 1, soap->id);
      data->digest = digest;
      /* omit indent for indented XML (next time around, we will catch '<') */
      if (*buf != '<')
        goto end;
    }
  }
  if (soap->event == SOAP_SEC_SIGN)
  { /* update smdevp engine */
    if (data->digest && data->digest->level)
    { soap_smd_update(soap, &data->digest->smd, buf, len);
      if (soap->level < data->digest->level)
      { soap->event = 0;
        soap_smd_final(soap, &data->digest->smd, (char*)data->digest->hash, NULL);
        data->digest->level = 0;
      }
    }
  }
end:
  if (data->fpreparesend)
    return data->fpreparesend(soap, buf, len);
  return SOAP_OK;
}

/**
@fn int soap_wsse_preparefinalsend(struct soap *soap)
@brief Collects the digests of all the wsu:Id elements and populates the SignedInfo.
@param soap context
@return SOAP_OK or fault

This callback is invoked just before the message is sent.
*/
static int
soap_wsse_preparefinalsend(struct soap *soap)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  DBGFUN("soap_wsse_preparefinalsend");
  if (!data)
    return SOAP_PLUGIN_ERROR;
  if (data->digest)
  { ds__SignatureType *signature = soap_wsse_Signature(soap);
    struct soap_wsse_digest *digest;
    const char *transform;
    int alg, signature_added = 0;
    /* if message is canonicalized populate transform element accordingly */
    if (soap->mode & SOAP_XML_CANONICAL)
      transform = c14n_URI;
    else
      transform = NULL;
    /* to increase the message length counter we need to emit the Signature,
       SignedInfo and SignatureValue elements. However, this does not work if
       we already populated the wsse:Signature with SignedInfo and should never
       happen! */
    if (!signature)
    { signature = soap_wsse_add_Signature(soap);
      signature_added = 1;
    }
    else if (signature->SignedInfo)
      return soap_set_receiver_error(soap, "wsse error", "Cannot use soap_wsse_sign with populated SignedInfo", SOAP_SSL_ERROR);
    /* digest hash strength is same as signature strength */
    alg = (SOAP_SMD_DGST | (data->sign_alg & SOAP_SMD_HASH));
    /* add the SignedInfo/Reference elements for each digest */
    for (digest = data->digest; digest; digest = digest->next)
      if (soap_wsse_add_SignedInfo_Reference(soap, digest->id, transform, NULL, alg, (char*)digest->hash))
        return soap->error;
    /* then compute the signature and add it */
    if (soap_wsse_add_SignatureValue(soap, data->sign_alg, data->sign_key, data->sign_keylen))
      return soap->error;
    /* Reset the callbacks and cleanup digests */
    soap_wsse_preparecleanup(soap, data);
    /* if non-chunked, adjust content length */
    if ((soap->mode & SOAP_IO) != SOAP_IO_CHUNK)
    { /* the code below ensures we increase the HTTP length counter */
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Counting the size of additional SOAP Header elements, mode=0x%x\n", soap->mode));
      if (signature_added)
      { soap->level = 3; /* indent level for XML Signature */
        if (soap->mode & SOAP_XML_CANONICAL && soap->mode & SOAP_XML_INDENT)
        { soap->ns = 0; /* need namespaces for canonicalization */
          soap->count += 4; /* correction for soap->ns = 0: add \n+indent */
	}
        soap_out_ds__SignatureType(soap, "ds:Signature", 0, signature, NULL);
      }
      else
      { const char *c14nexclude = soap->c14nexclude;
        soap->c14nexclude = "ds"; /* don't add xmlns:ds to count msg len */
        soap->level = 4; /* indent level for XML SignedInfo */
        if (soap->mode & SOAP_XML_CANONICAL && soap->mode & SOAP_XML_INDENT)
        { soap->ns = 0; /* need namespaces for canonicalization */
          soap->count += 5; /* correction for soap->ns = 0: add \n+indent */
	}
        soap_out_ds__SignedInfoType(soap, "ds:SignedInfo", 0, signature->SignedInfo, NULL);
        soap_outstring(soap, "ds:SignatureValue", 0, &signature->SignatureValue, NULL, 0);
        soap->c14nexclude = c14nexclude;
      }
    }
  }
  else /* Reset the callbacks and cleanup digests */
    soap_wsse_preparecleanup(soap, data);
  if (soap->fpreparefinalsend)
    return soap->fpreparefinalsend(soap);
  return SOAP_OK;
}

/**
@fn void soap_wsse_preparecleanup(struct soap *soap, struct soap_wsse_data *data)
@brief Restores engine state.
@param soap context
@param[in,out] data plugin data
*/
static void
soap_wsse_preparecleanup(struct soap *soap, struct soap_wsse_data *data)
{ struct soap_wsse_digest *digest, *next;
  DBGFUN("soap_wsse_preparecleanup");
  data->sign_alg = SOAP_SMD_NONE;
  data->sign_key = NULL;
  data->sign_keylen = 0;
  if (soap->fpreparesend == soap_wsse_preparesend)
    soap->fpreparesend = data->fpreparesend;
  if (soap->fpreparefinalsend == soap_wsse_preparefinalsend)
    soap->fpreparefinalsend = data->fpreparefinalsend;
  data->fpreparesend = NULL;
  data->fpreparefinalsend = NULL;
  for (digest = data->digest; digest; digest = next)
  { next = digest->next;
    SOAP_FREE(soap, digest);
  }
  data->digest = NULL;
}

/**
@fn int soap_wsse_preparefinalrecv(struct soap *soap)
@brief Verify signature and SignedInfo digests initiated with soap_wsse_verify_auto.
@param soap context
@return SOAP_OK or fault
@see soap_wsse_verify_auto

This callback is invoked just after a message was received.
*/
static int
soap_wsse_preparefinalrecv(struct soap *soap)
{ struct soap_wsse_data *data = (struct soap_wsse_data*)soap_lookup_plugin(soap, soap_wsse_id);
  ds__SignedInfoType *signedInfo = soap_wsse_SignedInfo(soap);
  soap->omode &= ~SOAP_SEC_WSUID;
  data->sigid = NULL; /* so we must set again before next send */
  data->encid = NULL; /* so we must set again before next send */
  DBGFUN("soap_wsse_preparefinalrecv");
  if (!data)
    return SOAP_PLUGIN_ERROR;
  if (data->deco_alg != SOAP_MEC_NONE && data->mec)
    if (soap_mec_end(soap, data->mec))
      return soap_wsse_fault(soap, wsse__FailedCheck, NULL);
  data->deco_alg = SOAP_MEC_NONE;
  if (signedInfo)
  { int err = SOAP_OK, alg, keylen = 0;
    EVP_PKEY *pkey = NULL;
    const void *key = NULL;
    /* determine which signature algorithm was used */
    if (soap_wsse_get_SignedInfo_SignatureMethod(soap, &alg))
      return soap->error;
    /* for HMAC-SHA1, the secret key might be stored in the KeyIdentifier */
    if ((alg & SOAP_SMD_ALGO) == SOAP_SMD_HMAC)
    { const char *valueType = soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifierValueType(soap);
      /* if in the KeyIdentifier, retrieve it */
      if (valueType && !strcmp(valueType, ds_hmac_sha1URI))
      { DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Using HMAC key from KeyIdentifier to verify signature\n"));
        key = soap_wsse_get_KeyInfo_SecurityTokenReferenceKeyIdentifier(soap, &keylen);
      }
      /* next, try the plugin's security token handler */
      if (!key)
      { if (data->security_token_handler)
        { DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Getting HMAC key through security_token_handler callback\n"));
          key = data->security_token_handler(soap, &alg, NULL, &keylen);
        }
      }
      /* still no key: try to get it from the plugin */
      if (!key && alg == (data->vrfy_alg & SOAP_SMD_MASK))
      { /* get the HMAC secret key from the plugin */
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Using HMAC key from plugin to verify signature\n"));
        key = data->vrfy_key;
        keylen = data->vrfy_keylen;
      }
    }
    else
    { /* get the certificate from the KeyInfo reference */
      X509 *cert, *cert1;
      cert = cert1 = soap_wsse_get_KeyInfo_SecurityTokenReferenceX509(soap);
      DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Got cert=%p\n", cert));
      /* next, try the plugin's security token handler */
      if (!cert)
      { if (data->security_token_handler)
        { DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Getting certificate through security_token_handler callback\n"));
          cert = (X509*)data->security_token_handler(soap, &alg, NULL, &keylen);
        }
      }
      /* obtain the public key from the cert */
      if (cert)
      { pkey = X509_get_pubkey((X509*)cert);
        key = (void*)pkey;
      }
      else if (alg == (data->vrfy_alg & SOAP_SMD_MASK))
      { /* get the public key from the plugin */
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, "Using public key from plugin to verify signature\n"));
        key = data->vrfy_key;
        soap->error = SOAP_OK;
      }
      if (cert1)
        X509_free(cert1);
    }
    /* if still no key, fault */
    if (!key)
      err = soap_wsse_fault(soap, wsse__SecurityTokenUnavailable, NULL);
    /* verify SignedInfo with signature and check digests of local elements */
    else if (soap_wsse_verify_SignatureValue(soap, alg, key, keylen)
          || soap_wsse_verify_SignedInfo(soap))
      err = soap->error;
    if (pkey)
      EVP_PKEY_free(pkey);
    if (err)
      return err;
    if (data->fpreparefinalrecv && data->fpreparefinalrecv != soap_wsse_preparefinalrecv)
      return data->fpreparefinalrecv(soap);
  }
  else if (!soap->fault)
    return soap_wsse_fault(soap, wsse__FailedCheck, "Signature required");
  return SOAP_OK;
}

#ifdef __cplusplus
}
#endif

