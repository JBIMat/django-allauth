Client ID Metadata Document
===========================

Support for the Client ID Metadata Document (`draft-ietf-oauth-client-id-metadata-document
<https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/>`_) can be
turned on via ``IDP_OIDC_CIMD_ENABLED``.

When enabled, clients can use an HTTPS URL as their ``client_id``. The
authorization server will fetch the metadata document from that URL to obtain the
client's registration information. No prior registration (such as Dynamic Client
Registration) is required. CIMD clients are always public clients and must use
PKCE.

The fetched metadata is cached for the duration specified by
``IDP_OIDC_CIMD_CACHE_TIMEOUT`` (default: 3600 seconds). Rate limiting and a
per-``client_id`` lock prevent excessive outbound fetches.

To restrict which URLs are accepted as a ``client_id``, override the
``is_cimd_url_allowed()`` adapter method.
