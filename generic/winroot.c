/*
 * winroot.c --
 *
 *	Windows ships few root certificates and fetches the rest from Windows
 *	Update when CryptoAPI builds a chain that needs one, so enumerating
 *	the ROOT store misses most of them. Backends that trust the system
 *	store ask here when they find no trusted issuer for a peer chain:
 *	they trust the root Windows found and use the intermediates it fetched
 *	for that chain only.
 */

#include <windows.h>
#include <wincrypt.h>
#include <string.h>

#include "tlsb.h"

/* Whether the peer sent this certificate. */
static int
Sent(const uint8_t *const *der, const size_t *len, int n, PCCERT_CONTEXT c)
{
    int i;

    for (i = 0; i < n; i++) {
	if (len[i] == c->cbCertEncoded
		&& memcmp(der[i], c->pbCertEncoded, len[i]) == 0) {
	    return 1;
	}
    }
    return 0;
}

int
tlsb_win_chain(const uint8_t *const *der, const size_t *len, int n,
	int server, void (*add)(void *ud, const uint8_t *der, size_t len,
	    int root),
	void *ud)
{
    /* Only the chain's trust; the backend checks dates, names and so on. */
    const DWORD bad = CERT_TRUST_IS_UNTRUSTED_ROOT
	    | CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_NOT_SIGNATURE_VALID
	    | CERT_TRUST_IS_REVOKED | CERT_TRUST_IS_EXPLICIT_DISTRUST
	    | CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_IS_CYCLIC;
    LPSTR usage = server ? szOID_PKIX_KP_CLIENT_AUTH
	    : szOID_PKIX_KP_SERVER_AUTH;
    PCCERT_CONTEXT leaf = NULL;
    HCERTSTORE extra = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA para;
    int i, got = 0;

    if (n < 1 || len[0] > MAXDWORD) {
	return 0;
    }
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
    leaf = CertCreateCertificateContext(X509_ASN_ENCODING, der[0],
	    (DWORD) len[0]);
    extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (leaf && extra) {
	for (i = 1; i < n; i++) {
	    if (len[i] <= MAXDWORD) {
		CertAddEncodedCertificateToStore(extra, X509_ASN_ENCODING,
			der[i], (DWORD) len[i], CERT_STORE_ADD_ALWAYS, NULL);
	    }
	}
	if (CertGetCertificateChain(NULL, leaf, NULL, extra, &para, 0, NULL,
		&chain) && chain->cChain > 0
		&& !(chain->TrustStatus.dwErrorStatus & bad)) {
	    PCERT_SIMPLE_CHAIN sc = chain->rgpChain[chain->cChain - 1];
	    DWORD top = sc->cElement - 1, k;

	    if (sc->rgpElement[top]->TrustStatus.dwInfoStatus
		    & CERT_TRUST_IS_SELF_SIGNED) {
		for (k = top; k >= 1; k--) {
		    PCCERT_CONTEXT c = sc->rgpElement[k]->pCertContext;

		    if (k == top || !Sent(der, len, n, c)) {
			add(ud, c->pbCertEncoded, c->cbCertEncoded, k == top);
			got++;
		    }
		}
	    }
	}
    }
    if (chain) CertFreeCertificateChain(chain);
    if (extra) CertCloseStore(extra, 0);
    if (leaf) CertFreeCertificateContext(leaf);
    return got;
}
