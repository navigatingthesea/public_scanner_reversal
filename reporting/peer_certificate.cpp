#include "../../common/review_contracts.hpp"

namespace ocean::reconstructed {
// UAy9caHUbZ.osM6fERXJBlG@0xf2ea80
bool certificate_name_is_mitmproxy(
    TextContracts& text,
    const CertificateName& name) {
    // Recovered: both comparisons trim Unicode/Go whitespace and use EqualFold.
    if (!text.equal_fold(text.trim_space(name.common_name), "mitmproxy"))
        return false;

    for (const auto& organization : name.organizations)
        if (text.equal_fold(text.trim_space(organization), "mitmproxy"))
            return true;
    return false;
}

// UAy9caHUbZ.kKuS2V@0xf2f420
bool certificate_is_mitmproxy(
    TextContracts& text,
    const CertificateNames& names) {
    return certificate_name_is_mitmproxy(text, names.issuer) ||
        certificate_name_is_mitmproxy(text, names.subject);
}

// Recovered check: a certificate side qualifies only when its common name and
// at least one organization both equal `mitmproxy`; issuer and subject are ORed.
// Empty organization lists fail. Eight complete ASCII fixtures covered ordinary
// success, early returns, and organization iteration. This predicate itself has
// no I/O and emits no report.
}
