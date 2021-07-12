package org.springframework.security.oauth2.provider.client;

/**
 * Type of the requested authentication method for the token endpoint.
 */
public enum TokenEndpointAuthMethod {
    /** The client is a public client as defined in OAuth 2.0, Section 2.1, and does not have a client secret */
    none,

    /** The client uses HTTP Basic as defined in OAuth 2.0, Section 2.3.1 */
    client_secret_basic,

    /** The client uses the HTTP POST parameters as defined in OAuth 2.0, Section 2.3.1.*/
    client_secret_post
}
