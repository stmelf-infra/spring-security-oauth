package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.company.oauth2.CustomAuthentication;
import org.company.oauth2.CustomOAuth2Authentication;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.SerializationStrategy;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.common.util.WhitelistedSerializationStrategy;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2ExpiringAuthentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.client.TokenEndpointAuthMethod;

public class JdbcAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {
	private JdbcAuthorizationCodeServices authorizationCodeServices;
	private JdbcClientDetailsService detailsService;
	private EmbeddedDatabase db;

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		detailsService = new JdbcClientDetailsService(db);
		authorizationCodeServices = new JdbcAuthorizationCodeServices(db, detailsService);
		BaseClientDetails client = new BaseClientDetails(
				"id",
				"resource",
				"profile",
				"email",
				"roles",
				"https://localhost:8443");
		client.setAuthCodeValiditySeconds(10);
		detailsService.addClientDetails(client);

		client = new BaseClientDetails(
				"id_public",
				"resource",
				"profile",
				"email",
				"roles",
				"https://localhost:8443");
		client.setAuthCodeValiditySeconds(2);
		client.setTokenEndpointAuthMethod(TokenEndpointAuthMethod.none);
		detailsService.addClientDetails(client);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Override
	AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}

	@Test
	public void testCustomImplementation() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);
		OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNotAllowedCustomImplementation() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy();
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
			assertNotNull(code);
			getAuthorizationCodeServices().consumeAuthorizationCode(code);
		}
		finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}

	@Test
	public void testPKCEValidation() {
		Map<String, String> requestParameters =
				Map.of("code_challenge", "ijiodwjieof", "code_challenge_method", "S256");
		OAuth2Request storedOAuth2Request = RequestTokenFactory
				.createOAuth2Request(requestParameters, "id_public", null, false, null, null, null, null, null);

		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);
		OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test(expected = InvalidGrantException.class)
	public void testPKCEValidationExpired() throws InterruptedException {
		Map<String, String> requestParameters =
				Map.of("code_challenge", "ijiodwjieof", "code_challenge_method", "S256");
		OAuth2Request storedOAuth2Request = RequestTokenFactory
				.createOAuth2Request(requestParameters, "id_public", null, false, null, null, null, null, null);

		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);
		Thread.sleep(3000);
		OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test(expected = InvalidRequestException.class)
	public void testPKCEChallengeMissing() {
		Map<String, String> requestParameters =
				Map.of("code_challenge_method", "S256");
		OAuth2Request storedOAuth2Request = RequestTokenFactory
				.createOAuth2Request(requestParameters, "id_public", null, false, null, null, null, null, null);

		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
	}

	@Test(expected = InvalidRequestException.class)
	public void testPKCEInvalidChallengeMethod() {
		Map<String, String> requestParameters =
				Map.of("code_challenge", "xxx", "code_challenge_method", "MD5");
		OAuth2Request storedOAuth2Request = RequestTokenFactory
				.createOAuth2Request(requestParameters, "id", null, false, null, null, null, null, null);

		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
	}

	@Test(expected = NoSuchClientException.class)
	public void testPKCEInvalidClient() {
		Map<String, String> requestParameters =
				Map.of("code_challenge", "xxx", "code_challenge_method", "MD5");
		OAuth2Request storedOAuth2Request = RequestTokenFactory
				.createOAuth2Request(requestParameters, "id_wrong", null, false, null, null, null, null, null);

		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test2", false));
		getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
	}


	@Test
	public void testCustomImplementationWithCustomStrategy() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new CustomOAuth2Authentication(
				storedOAuth2Request,
				new CustomAuthentication("test3", false));

		AuthorizationCodeServices jdbcAuthorizationCodeServices = getAuthorizationCodeServices();
		List<String> allowedClasses = new ArrayList<String>();
		allowedClasses.add("java.util.");
		allowedClasses.add("org.springframework.security.");
		allowedClasses.add("org.company.oauth2.CustomOAuth2AccessToken");
		allowedClasses.add("org.company.oauth2.CustomOAuth2Authentication");
		allowedClasses.add("org.company.oauth2.CustomAuthentication");
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy(allowedClasses);
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			String code = jdbcAuthorizationCodeServices.createAuthorizationCode(expectedAuthentication);
			assertNotNull(code);

			OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
			assertEquals(expectedAuthentication, actualAuthentication);
		}
		finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}
}
