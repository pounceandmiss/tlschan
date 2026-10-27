
[//000000001]: # (tlschan \- TLS channels for Tcl 9)
[//000000002]: # (Generated from file 'tlschan\.man' by tcllib/doctools with format 'markdown')
[//000000003]: # (tlschan\(n\) 0\.1 tlschan "TLS channels for Tcl 9")

# NAME

tlschan \- TLS 1\.2 and 1\.3 channels on wolfSSL, rustls, Mbed TLS or OpenSSL

# <a name='toc'></a>Table Of Contents

  - [Table Of Contents](#toc)

  - [Synopsis](#synopsis)

  - [Description](#section1)

  - [COMMANDS](#section2)

  - [OPTIONS](#section3)

  - [CALLBACKS](#section4)

  - [CHANNEL BEHAVIOUR](#section5)

  - [SESSION RESUMPTION](#section6)

  - [BACKEND DIFFERENCES](#section7)

  - [COMPATIBILITY](#section8)

      - [tcltls](#subsection1)

      - [tclmtls](#subsection2)

  - [ERRORS](#section9)

  - [STATIC LINKING](#section10)

  - [EXAMPLES](#section11)

  - [See Also](#seealso)

  - [Keywords](#keywords)

  - [Category](#category)

# <a name='synopsis'></a>SYNOPSIS

package require Tcl 9\.0  
package require tlschan ?0\.1?  
package require tlschan::wolfssl ?0\.1?  
package require tlschan::rustls ?0\.1?  
package require tlschan::mbedtls ?0\.1?  
package require tlschan::openssl ?0\.1?  

[__tlschan::socket__ ?*option value \.\.\.*? *host* *port*](#1)  
[__tlschan::socket__ __\-server__ *command* ?*option value \.\.\.*? *port*](#2)  
[__tlschan::import__ *channel* ?*option value \.\.\.*?](#3)  
[__tlschan::starttls__ *channel* ?*option value \.\.\.*?](#4)  
[__tlschan::unimport__ *channel*](#5)  
[__tlschan::unstack__ *channel*](#6)  
[__tlschan::handshake__ *channel*](#7)  
[__tlschan::status__ ?__\-local__? *channel*](#8)  
[__tlschan::connection__ *channel*](#9)  
[__tlschan::init__ ?*option value \.\.\.*?](#10)  
[__tlschan::ciphers__ ?*protocol*? ?*verbose*? ?*supported*?](#11)  
[__tlschan::protocols__](#12)  
[__tlschan::version__](#13)  
[__tlschan::exporter__ *channel* *label* *length* ?*context*?](#14)  
[__tlschan::randombytes__ *count*](#15)  
[__tlschan::aesgcm\-encrypt__ *key* *plaintext*](#16)  
[__tlschan::aesgcm\-decrypt__ *key* *data*](#17)  
[__tlschan::pbkdf2__ *digest* *password* *salt* *iterations* *length*](#18)  
[__tlschan::pkgconfig__ __list__](#19)  
[__tlschan::pkgconfig__ __get__ *key*](#20)  
[__tlschan::backend__](#21)  

# <a name='description'></a>DESCRIPTION

These packages add TLS to Tcl channels by stacking a TLS layer on a socket or
any other bidirectional channel\. Four backend packages share one channel layer
and one command set and differ only in the TLS library underneath:

  - __tlschan::wolfssl__

    wolfSSL\.

  - __tlschan::rustls__

    rustls with the ring crypto provider\.

  - __tlschan::mbedtls__

    Mbed TLS 3\.6\.

  - __tlschan::openssl__

    OpenSSL 3\.

Normally a program loads __tlschan__, which loads one backend and makes its
commands __::tlschan::__*name*\. This page writes the commands that way\.
Each backend package also defines them in the namespace of its own name, such as
__::tlschan::wolfssl__, with the same syntax; requiring a backend directly
pins it\. Several backends can be loaded into one interpreter, together with
tcltls \(package __tls__\)\.

__tlschan__ takes the backends in the order given by the variable
__::tlschan::prefer__, set before loading it, else by the environment
variable __TLSCHAN\_BACKEND__, else __openssl rustls mbedtls wolfssl__\.
The first of them already loaded is chosen, else the first that loads\. If none
does, __package require tlschan__ raises __no TLS backend available \(tried
openssl, rustls, mbedtls, wolfssl\)__ with errorCode __TLS BACKEND__\.

    namespace eval tlschan {variable prefer {mbedtls openssl}}
    package require tlschan

Unless the command __::tls::socket__ exists already, __tlschan__ also
creates aliases __::tls::__*name* for the chosen backend's commands, so
that code written for tcltls runs unchanged\. A tcltls loaded afterwards replaces
them\. A backend package by itself never touches __::tls__\. See
[COMPATIBILITY](#section8) for differences from tcltls and tclmtls\.

Only TLS 1\.2 and TLS 1\.3 are implemented\. By default a client opened with
__tlschan::socket__ verifies the server's certificate chain against the
system trust store and checks that the certificate matches the host name it
connected to\.

# <a name='section2'></a>COMMANDS

  - <a name='1'></a>__tlschan::socket__ ?*option value \.\.\.*? *host* *port*

    Opens a TCP connection with __::socket__ and stacks TLS on it with
    __tlschan::import__\. Returns the channel name\. __\-async__ \(which
    takes no value\), __\-myaddr__ and __\-myport__ go to __::socket__\.
    __\-autoservername__ *bool*, default __1__, sets
    __\-servername__ to *host* when it is not given\. All other options,
    after the defaults set with __tlschan::init__, go to
    __tlschan::import__; see [OPTIONS](#section3)\.

    Errors from __::socket__ \(for example __couldn't open socket:
    connection refused__\) and from __tlschan::import__ are raised
    unchanged; when the import fails the socket is closed\. The handshake is not
    part of this command: it runs on first use of the channel, see [CHANNEL
    BEHAVIOUR](#section5)\. With __\-async__, a failed connect is reported
    there, as in __handshake failed: connection refused__\.

  - <a name='2'></a>__tlschan::socket__ __\-server__ *command* ?*option value \.\.\.*? *port*

    Opens a listening socket with __::socket \-server__ and returns it\.
    __\-myaddr__, __\-reuseaddr__ and __\-reuseport__ are passed to
    __::socket__; __\-backlog__ is not supported\. Every accepted
    connection is imported with __\-server__ __1__, __\-model__ set to
    the listening socket, and the other options, then *command* is called with
    the channel, the client address and the client port appended, as for
    __::socket \-server__\.

    So all accepted connections share one configuration, and with it one session
    ticket key \(see [SESSION RESUMPTION](#section6)\): the first connection
    reads the files and evaluates the __\-password__ script, and later ones
    reuse the result\. An import error \(an unreadable __\-certfile__, for
    example\) closes that connection, is reported through __bgerror__, and
    *command* is not called; the next connection tries again\. A __\-model__
    given here replaces the listening socket\.

  - <a name='3'></a>__tlschan::import__ *channel* ?*option value \.\.\.*?

  - <a name='4'></a>__tlschan::starttls__ *channel* ?*option value \.\.\.*?

    Stacks a TLS layer on *channel* and returns the channel name, which is
    unchanged\. *channel* can be any channel open for reading and writing\. No
    data is exchanged until the handshake starts, see [CHANNEL
    BEHAVIOUR](#section5)\. The options are described in
    [OPTIONS](#section3)\. __starttls__ is another name for
    __import__\.

    Options are checked and files loaded here: a bad option, file or password
    raises an error from this command and leaves the channel as it was\.

  - <a name='5'></a>__tlschan::unimport__ *channel*

  - <a name='6'></a>__tlschan::unstack__ *channel*

    Sends a close\_notify alert if the handshake has completed, writes out
    pending TLS data and removes the TLS layer\. The channel stays open and
    carries plain data from then on\. Raises __bad channel "chan": not a TLS
    channel__ \(errorCode __TLS CHANNEL__\) if the topmost layer of
    *channel* is not TLS\. __unstack__ is another name for
    __unimport__\.

  - <a name='7'></a>__tlschan::handshake__ *channel*

    Advances the handshake\. Returns __1__ once the handshake has completed
    and __0__ if it is still in progress, which happens in nonblocking mode
    and inside the channel's __\-validatecommand__; otherwise the command
    waits for the handshake to finish\. If the handshake failed, raises its error
    message, such as __handshake failed: certificate verify failed:
    certificate has expired__, with errorCode __TLS HANDSHAKE__\. A failed
    channel raises the same error on every later call\.

  - <a name='8'></a>__tlschan::status__ ?__\-local__? *channel*

    Returns a dictionary describing the session and the peer's certificate, or
    with __\-local__ the local certificate\. The dictionary is empty until the
    handshake has completed, and stays empty if it failed\. The certificate keys
    are missing when there is no such certificate, for example on a server whose
    client sent none\. Session keys:

      * __protocol__ *string*

        __TLSv1\.2__ or __TLSv1\.3__, as in tcltls\.

      * __cipher__ *name*

        IANA name of the cipher suite, such as __TLS\_AES\_256\_GCM\_SHA384__\.

      * __sbits__ *n*

        Key size of the symmetric cipher in bits: __128__ or __256__\.

      * __alpn__ *protocol*

        The protocol agreed through ALPN, or an empty string\.

      * __servername__ *name*

        On a client the __\-servername__ in use; on a server the name the
        client sent in the SNI extension\. Empty if there is none\.

    The certificate keys are the same as in the *cert* argument of the
    __\-validatecommand__ callback:

      * __certificate__ *pem*

        The certificate in PEM format\.

      * __sha1\_hash__ *hex*

      * __sha256\_hash__ *hex*

        SHA\-1 and SHA\-256 digest of the DER certificate, in upper case hex\.

      * __subject__ *dn*

      * __issuer__ *dn*

        Distinguished names in RFC 2253 form, most significant part last, as in
        __CN=localhost,O=Example,C=US__\. Special characters are escaped with
        a backslash; attributes of unknown type appear as
        *oid*__=\#__*hex*\.

      * __serialNumber__ *hex*

      * __serial__ *hex*

        The serial number in upper case hex without leading zeros, preceded by
        __\-__ if negative\. __serial__ is the tcltls 1\.7 name\.

      * __version__ *n*

        Certificate version, normally __3__\.

      * __signatureAlgorithm__ *name*

      * __signature__ *name*

        Signature algorithm of the certificate \(outer and inner field\), such as
        __sha256WithRSAEncryption__ or __ecdsa\-with\-SHA256__; unknown
        algorithms appear as dotted OIDs\.

      * __notBefore__ *time*

      * __notAfter__ *time*

        Validity period as __Oct 15 08:03:54 2026 GMT__; the day of the
        month is padded to two characters with a space\.

      * __self\_signed__ *bool*

        Whether issuer and subject are the same name\.

      * __publicKeyAlgorithm__ *name*

        Such as __rsaEncryption__, __id\-ecPublicKey__ or
        __ED25519__\.

      * __bits__ *n*

        Size of the public key: the RSA modulus length, or the curve size for
        elliptic curve keys \(__256__ for P\-256\)\. Missing if unknown\.

      * __extensions__ *list*

        Names of the certificate's extensions in certificate order, dotted OIDs
        for unknown ones\.

      * __num\_extensions__ *n*

        Length of that list\.

      * __subjectAltName__ *list*

        Subject alternative names, each as __DNS:__*name*, __IP
        Address:__*address*, __email:__*address*, __URI:__*uri*,
        __DirName:__*/name* or __Registered ID:__*oid*\. IPv6
        addresses are written as eight colon separated hex groups\. Missing
        without the extension\.

      * __subjectKeyIdentifier__ *hex*

      * __authorityKeyIdentifier__ *hex*

        Key identifiers in upper case hex\. Missing without the extension\.

      * __ocsp__ *list*

        OCSP responder URLs from the authority information access extension\.
        Missing if there are none\.

      * __ca__ *bool*

        The CA flag of the basic constraints extension; __0__ without it\.

  - <a name='9'></a>__tlschan::connection__ *channel*

    Returns a dictionary with the state of the connection, available at any
    time:

      * __state__ *state*

        __handshake__, __open__ or __failed__\.

      * __is\_server__ *bool*

        Whether the channel is the server side\.

      * __servername__ *name*

        As in __status__; before the handshake has completed, the
        __\-servername__ given\. Absent when the state is __failed__\.

      * __error__ *message*

        Only when the state is __failed__: the error message\.

      * __protocol__ __cipher__ __sbits__ __alpn__

        Only when the state is __open__: as in __status__\.

      * __session\_reused__ *bool*

        Only when the state is __open__: whether the session was resumed,
        see [SESSION RESUMPTION](#section6)\.

  - <a name='10'></a>__tlschan::init__ ?*option value \.\.\.*?

    Sets the default options of __tlschan::socket__, both forms\. Each call
    replaces the previous defaults; without arguments it removes them\.
    __\-model__, __\-server__ and __\-servername__ are dropped\. The
    options are not checked until __socket__ uses them\.
    __tlschan::import__ does not use these defaults\. Returns an empty
    string\.

  - <a name='11'></a>__tlschan::ciphers__ ?*protocol*? ?*verbose*? ?*supported*?

    Returns the IANA names of the cipher suites the library offers for
    certificate based key exchange\. *protocol* is one of __ssl2__,
    __ssl3__, __tls1__, __tls1\.1__, __tls1\.2__ or
    __tls1\.3__; the list is empty for the first four\. Without *protocol*,
    suites of both TLS 1\.2 and TLS 1\.3 are returned\. *verbose* and
    *supported* are accepted for compatibility and ignored\.

  - <a name='12'></a>__tlschan::protocols__

    Returns the protocols that can be enabled: __tls1\.2 tls1\.3__\.

  - <a name='13'></a>__tlschan::version__

    Returns the name and version of the TLS library, such as __wolfSSL
    5\.9\.4__, __rustls 0\.23\.46__, __Mbed TLS 3\.6\.7__ or __OpenSSL
    3\.6\.5__\.

  - <a name='14'></a>__tlschan::exporter__ *channel* *label* *length* ?*context*?

    Returns *length* bytes of keying material exported from the session as
    defined by RFC 5705 \(TLS 1\.2\) and RFC 8446 section 7\.5 \(TLS 1\.3\)\. *length*
    is 1 to 8160; *context* is a byte string\. With TLS 1\.2 leaving out
    *context* gives a different result from an empty one; with TLS 1\.3 the two
    are the same\. Errors: __the TLS handshake has not completed__ \(errorCode
    __TLS WRONGSTATE__\), __length must be between 1 and 8160__ \(__TLS
    WRONGARGS__\) and __keying material export failed__ \(__TLS
    EXPORT__\)\.

  - <a name='15'></a>__tlschan::randombytes__ *count*

    Returns *count* bytes, 0 to 1048576, from the library's random number
    generator\.

  - <a name='16'></a>__tlschan::aesgcm\-encrypt__ *key* *plaintext*

    Encrypts *plaintext* with AES\-256\-GCM, without associated data\. *key*
    must be 32 bytes\. Returns a fresh random 12 byte nonce, the ciphertext and
    the 16 byte tag, concatenated: 28 bytes more than *plaintext*\.

  - <a name='17'></a>__tlschan::aesgcm\-decrypt__ *key* *data*

    Reverses __aesgcm\-encrypt__: *data* is nonce, ciphertext and tag as
    returned by it\. Raises __ciphertext too short__ if *data* has fewer
    than 28 bytes and __AES\-GCM authentication failed__ if the tag does not
    match\.

  - <a name='18'></a>__tlschan::pbkdf2__ *digest* *password* *salt* *iterations* *length*

    Derives *length* bytes, 1 to 64, from *password* and *salt* with
    PBKDF2 \(RFC 8018\)\. *digest* is __sha1__, __sha256__ or
    __sha512__, the HMAC hash\. *iterations* is 1 to 10000000\.

    The arguments and results of __randombytes__, __aesgcm\-encrypt__,
    __aesgcm\-decrypt__ and __pbkdf2__ are byte strings; a character
    above U\+00FF raises a Tcl error, so convert text with __encoding convertto
    utf\-8__ first\. Their own errors have errorCode __TLS CRYPTO__\.

  - <a name='19'></a>__tlschan::pkgconfig__ __list__

  - <a name='20'></a>__tlschan::pkgconfig__ __get__ *key*

    Build information as registered with __Tcl\_RegisterConfig__\. Keys:
    __version__, the package version \(__0\.1\.0__\), and __backend__,
    one of __wolfssl__, __rustls__, __mbedtls__ or __openssl__\.

  - <a name='21'></a>__tlschan::backend__

    Only in __tlschan__: returns the name of the backend it loaded, such as
    __openssl__\.

# <a name='section3'></a>OPTIONS

These options are accepted by __import__ and __starttls__, by
__socket__ and by __init__\. Boolean values are any form Tcl accepts\. An
empty value counts as not given for __\-cadir__, __\-cafile__,
__\-cert__, __\-certfile__, __\-cipher__, __\-ciphersuites__,
__\-command__, __\-key__, __\-keyfile__, __\-model__,
__\-password__, __\-servername__, __\-validatecommand__ and
__\-vcmd__\.

  - __\-alpn__ *list*

    Protocol names to negotiate with ALPN \(RFC 7301\), such as __h2
    http/1\.1__\. Each name must be 1 to 255 bytes long, or __import__
    raises __invalid ALPN protocol name ""__ \(errorCode __TLS CONFIG__\)\.
    Which common name is chosen depends on the backend, see [BACKEND
    DIFFERENCES](#section7)\. With none in common the handshake completes
    without ALPN\.

  - __\-autoservername__ *bool*

    Only meaningful to __socket__, see there\. __import__ ignores it\.

  - __\-cadir__ *directory*

    A directory of trusted CA certificates\. The TLS library reads it directly,
    so it must be a native path, not one inside a Tcl virtual filesystem\. The
    expected file names differ, see [BACKEND DIFFERENCES](#section7)\.
    __\-cadir__ and __\-cafile__ can be combined\.

  - __\-cafile__ *file*

    Trusted CA certificates: a PEM file with any number of them, or one DER
    certificate\. The file is read through Tcl's filesystem, so it can be inside
    zipfs or another virtual filesystem\.

    Without __\-cafile__ and __\-cadir__ the system trust store is used,
    read when first needed\. Where it comes from depends on the backend, see
    [BACKEND DIFFERENCES](#section7)\.

  - __\-cert__ *data*

    The local certificate as data: PEM text, which may hold the leaf certificate
    followed by intermediates to be sent along, or a single DER certificate\.
    Takes precedence over __\-certfile__\.

  - __\-certfile__ *file*

    As __\-cert__, read from a file through Tcl's filesystem\.

  - __\-cipher__ *list*

    The TLS 1\.2 cipher suites to enable, replacing the default ones\. The list
    holds suite names separated by colons, commas or white space: IANA names as
    __ciphers__ returns them
    \(__TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_GCM\_SHA256__\), the same with __\-__
    for __\___, OpenSSL names \(__ECDHE\-ECDSA\-AES128\-GCM\-SHA256__\) or the
    library's own names, in any letter case\. OpenSSL cipher string syntax
    \(__HIGH__, __\!aNULL__, __@STRENGTH__\) is not supported\. An
    unknown name raises __unknown cipher: __*name* \(errorCode __TLS
    CONFIG__\)\.

  - __\-ciphersuites__ *list*

    The TLS 1\.3 cipher suites to enable, replacing the default ones, in the same
    form, such as __TLS\_CHACHA20\_POLY1305\_SHA256__\.

    Names of either protocol may appear in either option: each name is sorted to
    its protocol, and the names a protocol receives replace its defaults\. A
    protocol that receives no names keeps its defaults, unless its own option
    was given: __\-cipher__ without a TLS 1\.2 name disables TLS 1\.2, and
    __\-ciphersuites__ without a TLS 1\.3 name disables TLS 1\.3\. If that
    leaves no protocol, __import__ raises __no usable cipher suites__
    \(errorCode __TLS CONFIG__\)\.

  - __\-command__ *prefix*

    A command prefix invoked on handshake completion and on failure, see
    [CALLBACKS](#section4)\.

  - __\-key__ *data*

    The private key as data, PEM or DER: PKCS\#8, PKCS\#1 \(RSA\) or SEC1 \(EC\)\.
    Takes precedence over __\-keyfile__\. A certificate and a key must be
    given together, and they must match\.

  - __\-keyfile__ *file*

    As __\-key__, read from a file through Tcl's filesystem\. Defaults to the
    __\-certfile__, so one PEM file can hold both\.

    An encrypted key needs __\-password__\. PKCS\#8 keys encrypted with PBES2,
    as written by __openssl pkcs8 \-topk8 \-v2 aes\-256\-cbc__, work with every
    backend, in PEM and DER form\. Other formats depend on the backend, see
    [BACKEND DIFFERENCES](#section7)\.

  - __\-model__ *channel*

    Use a shared configuration: certificates, keys, password, trust, protocols,
    cipher suites, ALPN, __\-request__ and __\-require__ come from it, and
    options of this call that configure them are ignored\. __\-servername__,
    __\-command__ and __\-validatecommand__ still apply\. *channel* can
    be any channel\. A TLS channel lends its own configuration\. Any other channel
    anchors one: the first import naming it creates the configuration from its
    options, later imports share it, and it is released when *channel* is
    closed; channels using it keep it\. __\-server__ must match the
    configuration, or __import__ raises __\-model __*channel* __is
    configured as a client__ \(or __server__\), errorCode __TLS MODEL__\.
    Sharing a configuration saves loading files again and is needed for session
    resumption, see [SESSION RESUMPTION](#section6)\.

  - __\-password__ *script*

    A script whose result is the password of the private key; the script may
    also end with __return__ *password*\. It is evaluated at global level,
    once, by the __import__ that creates a configuration with a key, whether
    or not the key is encrypted\. An error in the script is raised by
    __import__\.

  - __\-request__ *bool*

    On a server, ask the client for a certificate\. Default __0__\. A
    certificate the client sends is then available through __status__
    whether or not it verifies, unless __\-require__ is set\. No effect on a
    client\.

  - __\-require__ *bool*

    On a client, verify the server's certificate chain and host name and fail
    the handshake if they do not verify\. Default __1__\. With __0__, no
    verification is done, unless __\-validatecommand__ is given\.

    On a server, require a client certificate that verifies against
    __\-cafile__, __\-cadir__ or the system store; implies
    __\-request__\. Default __0__\.

  - __\-server__ *bool*

    Act as the server side\. Default __0__\. A server needs a certificate and
    a private key, or __import__ raises an error\.

  - __\-servername__ *name*

    On a client, the name sent in the SNI extension and the name the server's
    certificate must match\. An IP address is matched against the certificate's
    IP address entries and is not sent as SNI\. Without __\-servername__ no
    SNI is sent and only the chain is verified, not the name; unlike
    __socket__, __import__ does not set it\. A value that is neither a
    host name nor an IP address raises __invalid server name
    "__*name*__"__ \(errorCode __TLS CONFIG__\)\. Servers ignore this
    option\.

  - __\-ssl2__ *bool*

  - __\-ssl3__ *bool*

  - __\-tls1__ *bool*

  - __\-tls1\.1__ *bool*

  - __\-castore__ *uri*

  - __\-dhparams__ *file*

  - __\-post\_handshake__ *bool*

  - __\-security\_level__ *n*

  - __\-session\_id__ *data*

    Accepted for tcltls compatibility and ignored; the old protocols are never
    enabled\.

  - __\-tls1\.2__ *bool*

  - __\-tls1\.3__ *bool*

    Enable TLS 1\.2 or TLS 1\.3\. Both default to __1__\. Disabling both raises
    __no protocols enabled__ \(errorCode __TLS PROTOCOL__\)\.

  - __\-validatecommand__ *prefix*

  - __\-vcmd__ *prefix*

    A command prefix that decides on each certificate the peer sends, see
    [CALLBACKS](#section4)\. A channel with this callback never resumes a
    session\.

# <a name='section4'></a>CALLBACKS

__\-command__ and __\-validatecommand__ are command prefixes: the
arguments below are appended and the command is evaluated at global level\. They
can run inside any command that does I/O on the channel, or from the event loop
when the channel is nonblocking\. An error in a callback is reported through
__bgerror__ \(see __interp bgerror__\); it does not become the result of
the command that triggered the callback\.

  - *prefix* __info__ *channel* __handshake__ __done__ __\{SSL negotiation finished successfully\}__ __info__

    __\-command__, once, when the handshake has completed\.

  - *prefix* __error__ *channel* *message*

    __\-command__, once, when the channel fails, during the handshake or
    later\. *message* is the error that I/O on the channel raises from then on\.

  - *prefix* __verify__ *channel* *depth* *cert* *ok* *error*

    __\-validatecommand__, during the handshake, for each certificate the
    peer sent, from the highest *depth* down to __0__, the peer's own
    certificate\. Certificates taken from the local trust store are not reported\.
    *cert* is a dictionary with the certificate keys of __status__\. *ok*
    is __1__ if the library accepts this certificate and __0__ if not;
    *error* then gives the reason, such as __certificate has expired__,
    __hostname mismatch__ or __issuer certificate not trusted__ for a
    certificate signed by a rejected one, and is empty otherwise\.

    A result that is a true boolean or a nonzero integer accepts the
    certificate\. Anything else, or an error, rejects it, and the handshake fails
    with __handshake failed: certificate rejected by validation callback__\.
    The result replaces the library's verdict whatever __\-require__ says:
    the callback can accept an expired or untrusted certificate or a name
    mismatch, and can reject a valid one\. A client calls it whenever it is
    given; a server only with __\-request__ or __\-require__, when the
    client sends a certificate\.

    The callback may use its channel, but the handshake is still in progress:
    __handshake__ returns __0__, reads return nothing, and what it
    writes is sent once the handshake has completed\.

The __\-password__ script is not a prefix: it is evaluated as given, without
arguments, see [OPTIONS](#section3)\.

# <a name='section5'></a>CHANNEL BEHAVIOUR

  - The TLS channel keeps the name of the channel below\. It adds no channel
    options of its own: __chan configure__ options other than the generic
    ones, such as __\-peername__, __\-sockname__ or __\-keepalive__,
    are those of the channel below\.

  - The handshake starts on first use\. On a blocking channel the first
    __read__, __gets__, __flush__ or __tlschan::handshake__
    performs the whole handshake and waits for it\. On a nonblocking channel the
    handshake proceeds from the event loop: at once if the channel was already
    nonblocking when imported, otherwise after the first read or write attempt
    or once a __chan event__ handler is set\. __tlschan::handshake__ also
    advances it\. Data written before it completes is buffered and sent
    afterwards\. Readable and writable handlers are not called before the
    handshake has completed or failed\.

  - A failure is final: every later __read__, __gets__, __puts__ or
    __flush__ raises the error, without errorCode, and a nonblocking channel
    becomes readable and writable to report it\. During the handshake the message
    is __handshake failed: __*reason*; afterwards __read failed:
    __*reason*, __write failed: __*reason*, __connection closed__
    or an operating system message such as __connection reset by peer__\.
    Either way it can also be __peer sent alert: __*description*\. Typical
    handshake reasons are __certificate verify failed: __*why*,
    __certificate rejected by validation callback__, __peer did not return
    a certificate__ and __connection closed during handshake__; *why* is
    one of __certificate has expired__, __certificate is not yet
    valid__, __hostname mismatch__, __self\-signed certificate__,
    __unable to get local issuer certificate__ or __issuer certificate not
    trusted__, or else the library's own words\.

  - In TLS 1\.3 a client's handshake completes before the server has checked the
    client certificate\. A rejection reaches the client as an alert on its next
    read, as in __peer sent alert: certificate required__\.

  - The end of the stream is reported as EOF both when the peer sent a
    close\_notify alert and when the connection was closed without one\.

  - __close__ sends a close\_notify alert if the handshake has completed,
    writes out pending data, blocking if needed, and closes the channel below\.
    Tcl refuses to half\-close a stacked channel: __close__ *channel*
    __write__ raises __half\-close not applicable to stack of
    transformations__\.

  - __fcopy__ and __chan copy__ work in both directions\.

# <a name='section6'></a>SESSION RESUMPTION

All backends resume sessions, in TLS 1\.2 and TLS 1\.3, by the same rules:

  - A server issues session tickets under a key that belongs to its
    configuration, so it resumes only sessions of connections that shared that
    configuration\. The connections accepted by one __socket \-server__ share
    one\.

  - A client keeps the most recent session for each server name, for up to 32
    names, in its configuration, and offers it on the next connection to the
    same __\-servername__ that uses this configuration\. A client therefore
    resumes only when its connections share a configuration through
    __\-model__, for example one anchored on a long\-lived channel:

    set model [file tempfile]
    proc https {args} {
        tlschan::socket -model $::model {*}$args
    }
    http::register https 443 https

  - There is no resumption for a client without __\-servername__, nor for a
    client or a server with __\-validatecommand__, whose callback must see
    every handshake\.

  - __connection__ reports whether a session was resumed as
    __session\_reused__\.

# <a name='section7'></a>BACKEND DIFFERENCES

The backends behave alike except for the following, observed with wolfSSL 5\.9\.4,
rustls 0\.23\.46, Mbed TLS 3\.6\.7 and OpenSSL 3\.6\.5\.

  - Cipher suites

    __tlschan::wolfssl__ and __tlschan::rustls__ have 3 TLS 1\.3 suites
    and 6 TLS 1\.2 suites, all ECDHE with AES\-GCM or ChaCha20\-Poly1305\.
    __tlschan::mbedtls__ and __tlschan::openssl__ add the CCM suites to
    TLS 1\.3 and offer many more TLS 1\.2 suites \(103 and 59 in the builds above\),
    including CBC, ARIA, Camellia, DHE and RSA key exchange; their lists depend
    on how the library was built\.

  - ALPN choice

    __tlschan::wolfssl__ chooses the first of the client's protocols that
    the server also lists; the others choose the first of the server's protocols
    that the client offers\.

  - __\-cadir__

    __tlschan::wolfssl__ and __tlschan::mbedtls__ load every certificate
    file in the directory\. __tlschan::rustls__ loads files named "\*\.pem",
    "\*\.crt" or like an OpenSSL hash link \("1a2b3c4d\.0"\)\.
    __tlschan::openssl__ needs an OpenSSL hashed directory \(see __openssl
    rehash__\) and finds only certificates under their hash names\.

  - Trust anchors

    __tlschan::openssl__ also accepts a certificate that is not a CA, given
    in __\-cafile__, as a trust anchor; the others do not\.

  - System trust store

    __tlschan::wolfssl__ uses the Windows or macOS store, elsewhere the
    certificates in "/etc/ssl/certs", "/etc/pki/ca\-trust/source/anchors" and
    "/etc/pki/tls/certs", or if none exists the bundle "/etc/ssl/cert\.pem" \(on
    Haiku "/boot/system/data/ssl/CARootCertificates\.pem"\); it ignores
    __SSL\_CERT\_FILE__ and __SSL\_CERT\_DIR__\. __tlschan::rustls__ uses
    rustls\-native\-certs, which honours __SSL\_CERT\_FILE__ and
    __SSL\_CERT\_DIR__, and falls back to Mozilla's root list when the system
    has none\. __tlschan::mbedtls__ reads __SSL\_CERT\_FILE__ and
    __SSL\_CERT\_DIR__ if set, else the first CA bundle found at the usual
    places, else "/etc/ssl/certs"; on Windows it uses the Windows certificate
    store, on macOS the keychain's trust settings\. __tlschan::openssl__ uses
    OpenSSL's default locations, which honour __SSL\_CERT\_FILE__ and
    __SSL\_CERT\_DIR__, then the usual bundle files, and on Windows with
    OpenSSL 3\.2 or later the Windows store\.

  - Encrypted keys

    Legacy encrypted PEM keys \(__Proc\-Type: 4,ENCRYPTED__\) and PKCS\#8 keys
    encrypted with PBES1, such as PBE\-SHA1\-3DES, work only with
    __tlschan::mbedtls__ and __tlschan::openssl__;
    __tlschan::wolfssl__ reports __unsupported key encryption__ for
    them\.

  - Refused client certificates

    The alert a server sends when it refuses a client certificate is the
    library's\. For a missing certificate it is __certificate required__ in
    TLS 1\.3; in TLS 1\.2 __tlschan::wolfssl__ and __tlschan::openssl__
    send __handshake failure__, __tlschan::rustls__ __certificate
    required__, and __tlschan::mbedtls__ closes the connection without an
    alert, so the client reports __connection closed during handshake__\. For
    an untrusted certificate it is __unknown CA__, from
    __tlschan::rustls__ __certificate unknown__\. A
    __tlschan::mbedtls__ server in TLS 1\.3 encrypts the alert with keys the
    client no longer reads with, so the client's next read fails with a MAC
    error instead \(an Mbed TLS bug\); the server still refuses\.

  - Received alerts

    __tlschan::mbedtls__ reports a received alert as __peer sent alert__
    without its name: Mbed TLS 3\.6 doesn't say which one arrived\.

# <a name='section8'></a>COMPATIBILITY

## <a name='subsection1'></a>tcltls

Code written for tcltls 2 mostly runs unchanged through the __::tls__
aliases of __tlschan__, or with __::tls__ replaced by __::tlschan__
or a backend's namespace\. The differences:

  - Not provided: __tls::shutdown__, __tls::misc__,
    __tls::build\-info__, the sample callbacks __tls::callback__,
    __tls::password__ and __tls::validate\_command__, and
    __tls::debug__\. Added: __exporter__, __randombytes__,
    __aesgcm\-encrypt__, __aesgcm\-decrypt__ and __pbkdf2__\.

  - __status__: __cipher__ is an IANA name, also for TLS 1\.2, where
    tcltls uses OpenSSL names; digests are upper case hex; __bits__ is the
    key size, not its security strength\. tcltls keys not listed under
    __status__, such as __peername__, __verifyResult__,
    __keyUsage__ or __all__, are absent; __self\_signed__,
    __ca__, __num\_extensions__ and __ocsp__ correspond to tcltls's
    __selfSigned__, __basicConstraintsCA__, __extCount__ and
    __ocspResponders__\.

  - __connection__: __state__ is __handshake__, __open__ or
    __failed__, not an OpenSSL state string, and only the keys listed there
    exist\.

  - __ciphers__ returns IANA names and ignores *verbose* and
    *supported*\.

  - __\-command__ reports only __info__ \(handshake completion\) and
    __error__; there are no __message__ and __session__ calls\.

  - __\-validatecommand__ is called only with __verify__, not with
    __alpn__, __hello__ or __sni__\. Any true result accepts; tcltls
    treats __2__ as rejecting without aborting\. Certificates from the local
    trust store are not reported\.

  - __\-password__ is evaluated without arguments; tcltls appends
    __password__, the read/write flag and the maximum length\.

  - __\-cert__ and __\-key__ take PEM as well as DER; __\-cafile__,
    __\-certfile__ and __\-keyfile__ are read through Tcl's filesystem\.

  - Options without an effect here are accepted and ignored, see
    [OPTIONS](#section3)\.

  - errorCodes begin with __TLS__, see [ERRORS](#section9)\.

## <a name='subsection2'></a>tclmtls

tclmtls is the package __mtls__ with commands in __::mtls__; its names
do not clash with these packages\. Compared with tclmtls:

  - There is nothing like __mtls::debug__ or __mtls::build\-info__\.

  - __tlschan::pkgconfig__ has only the keys __version__ and
    __backend__; tclmtls's __client__, __server__,
    *proto*__,protocol__ and __version,backend__,
    __name,backend__, __type,backend__ are absent\.

  - __status__ returns more keys, and cipher suites, there and in
    __ciphers__, are IANA names \(__TLS\_AES\_256\_GCM\_SHA384__\) instead of
    Mbed TLS names \(__TLS1\-3\-AES\-256\-GCM\-SHA384__\)\.

  - errorCodes begin with __TLS__ instead of __MTLS__, and errors of the
    crypto commands are just __TLS CRYPTO__, without a further element\. The
    crypto commands take and return data in the same formats and with the same
    limits\.

# <a name='section9'></a>ERRORS

Errors raised by the commands have these errorCodes:

  - __TLS CONFIG__

    An invalid option value: unparsable certificate, key or CA file, wrong
    password, unknown cipher suite, invalid ALPN name or server name, missing
    certificate on a server\.

  - __TLS PROTOCOL__

    No protocol enabled\.

  - __TLS MODEL__

    The __\-model__ configuration is for the other side, client or server\.

  - __TLS IMPORT__

    The session could not be set up\.

  - __TLS CHANNEL__

    The channel is not a TLS channel\.

  - __TLS HANDSHAKE__

    Raised by __handshake__ for a failed handshake\.

  - __TLS WRONGSTATE__ __TLS WRONGARGS__ __TLS EXPORT__

    Raised by __exporter__\.

  - __TLS CRYPTO__

    Raised by the crypto commands\.

  - __TLS INIT__

    The library could not be initialised when loading the package\.

  - __TLS BACKEND__

    __tlschan__ found no backend to load\.

Errors opening a file named in an option have a __POSIX__ errorCode; errors
in arguments have the usual __TCL__ ones\. I/O errors on the channel do not
set errorCode, see [CHANNEL BEHAVIOUR](#section5)\.

# <a name='section10'></a>STATIC LINKING

Built with __BUILD\_SHARED\_LIBS=OFF__, each backend is an archive, such as
"libtcl9tlschan\_wolfssl0\.1\.0\.a", whose only global symbol is its initialisation
function: __Tlschan\_wolfssl\_Init__, __Tlschan\_rustls\_Init__,
__Tlschan\_mbedtls\_Init__ or __Tlschan\_openssl\_Init__\. The archive uses
Tcl's stubs interface, so the application also links Tcl's stub library; the
pkg\-config file "tcl9tlschan\_wolfssl\.pc" \(and so on\) names the other libraries
to link\. The application registers the package and declares it in each
interpreter that is to use it:

    Tcl_StaticLibrary(NULL, "Tlschan_wolfssl", Tlschan_wolfssl_Init, NULL);
    Tcl_EvalEx(interp,
        "package ifneeded tlschan::wolfssl 0.1.0 {load {} Tlschan_wolfssl}", -1, 0);

Pass NULL, not an interpreter: with one, Tcl takes the package as already loaded
there and never calls __Tlschan\_wolfssl\_Init__\. There is no safe\-interpreter
initialisation function\.

__tlschan__ is a script, installed with its "pkgIndex\.tcl" in
"lib/tlschan0\.1\.0" for static builds too\. An application ships it in its script
library, next to the backends it registers, and __package require tlschan__
then picks among those\. See "README\.md" for building\.

# <a name='section11'></a>EXAMPLES

Fetch a page over HTTPS, verifying the server against the system store:

    package require tlschan
    package require http
    http::register https 443 ::tlschan::socket
    set tok [http::geturl https://www.tcl-lang.org/]
    puts [http::ncode $tok]
    http::cleanup $tok

An echo server, event driven:

    package require tlschan

    proc accept {chan addr port} {
        chan configure $chan -blocking 0 -buffering line
        chan event $chan readable [list echo $chan]
    }

    proc echo {chan} {
        if {[catch {gets $chan line} n]} {
            puts stderr "$chan: $n"
            close $chan
        } elseif {$n >= 0} {
            puts $chan $line
        } elseif {[eof $chan]} {
            close $chan
        }
    }

    set opts {-certfile server.pem -keyfile server-key.pem}
    tlschan::socket -server accept {*}$opts 8443
    vwait forever

Switch an established plain connection to TLS, as after a STARTTLS command;
__\-servername__ must be given explicitly:

    package require tlschan
    set chan [socket mail.example.com 587]
    # ... plain text exchange ending in STARTTLS ...
    tlschan::starttls $chan -servername mail.example.com
    tlschan::handshake $chan

Accept a server only if its certificate has a known SHA\-256 fingerprint, such as
one shown by __openssl x509 \-noout \-fingerprint \-sha256__\. This one pins the
backend by requiring it directly:

    package require tlschan::mbedtls

    proc pin {fingerprint op chan depth cert ok error} {
        if {$depth > 0} {
            return 1
        }
        set expected [string map {: ""} $fingerprint]
        string equal -nocase $expected [dict get $cert sha256_hash]
    }

    set vcmd [list pin $fingerprint]
    set chan [tlschan::mbedtls::socket -validatecommand $vcmd device.local 8443]

Mutual TLS: the server requires a client certificate issued by its CA and greets
the client by name\.

    package require tlschan

    proc accept {chan addr port} {
        chan configure $chan -blocking 0 -buffering line
        chan event $chan readable [list greet $chan]
    }

    proc greet {chan} {
        if {[catch {gets $chan line} n] || [eof $chan]} {
            close $chan
        } elseif {$n >= 0} {
            puts $chan "hello [dict get [tlschan::status $chan] subject]"
        }
    }

    set opts {-certfile server.pem -keyfile server-key.pem}
    tlschan::socket -server accept -require 1 -cafile client-ca.pem {*}$opts 8443
    vwait forever

The client:

    package require tlschan
    set opts {-certfile client.pem -keyfile client-key.pem}
    set chan [tlschan::socket -cafile server-ca.pem {*}$opts server.example.com 8443]
    chan configure $chan -buffering line
    puts $chan hi
    puts [gets $chan]

Code written for tcltls, unchanged:

    package require tlschan
    set chan [tls::socket www.tcl-lang.org 443]

# <a name='seealso'></a>SEE ALSO

chan, http, socket

# <a name='keywords'></a>KEYWORDS

ALPN, Mbed TLS, OpenSSL, SSL, TLS, X\.509, certificate, channel, https, rustls,
socket, wolfSSL

# <a name='category'></a>CATEGORY

Networking
