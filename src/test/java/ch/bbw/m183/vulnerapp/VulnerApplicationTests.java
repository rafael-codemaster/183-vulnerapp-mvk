package ch.bbw.m183.vulnerapp;

import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VulnerApplicationTests implements WithAssertions {

	@LocalServerPort
	private int port;

	WebTestClient webTestClient;

	@BeforeEach
	void setUpClient() {
		webTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
	}

	@Test
	void rootAccessMatrix() {
		webTestClient.get().uri("/").exchange().expectStatus().isOk();
		var user = login("fuu", "BarbarossA123");
		webTestClient.get().uri("/").cookie("JSESSIONID", user.sessionId()).exchange().expectStatus().isOk();
		webTestClient.get().uri("/")
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.exchange()
			.expectStatus().isOk();
		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient.get().uri("/").cookie("JSESSIONID", admin.sessionId()).exchange().expectStatus().isOk();
		webTestClient.get().uri("/")
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void blogGetAccessMatrix() {
		webTestClient.get().uri("/api/blog").exchange().expectStatus().isOk();
		var user = login("fuu", "BarbarossA123");
		webTestClient.get().uri("/api/blog").cookie("JSESSIONID", user.sessionId()).exchange().expectStatus().isOk();
		webTestClient.get().uri("/api/blog")
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.exchange()
			.expectStatus().isOk();
		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient.get().uri("/api/blog").cookie("JSESSIONID", admin.sessionId()).exchange().expectStatus().isOk();
		webTestClient.get().uri("/api/blog")
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void blogPostAccessMatrix() {
		webTestClient.post().uri("/api/blog")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("{\"title\":\"x\",\"body\":\"y\"}")
			.exchange()
			.expectStatus().isUnauthorized();

		var user = login("fuu", "BarbarossA123");
		webTestClient.post().uri("/api/blog")
			.contentType(MediaType.APPLICATION_JSON)
			.cookie("JSESSIONID", user.sessionId())
			.bodyValue("{\"title\":\"x\",\"body\":\"y\"}")
			.exchange()
			.expectStatus().isForbidden();

		webTestClient.post().uri("/api/blog")
			.contentType(MediaType.APPLICATION_JSON)
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.bodyValue("{\"title\":\"My safe post\",\"body\":\"Hello world\"}")
			.exchange()
			.expectStatus().isCreated();

		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient.post().uri("/api/blog")
			.contentType(MediaType.APPLICATION_JSON)
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.bodyValue("{\"title\":\"Admin post\",\"body\":\"admin body\"}")
			.exchange()
			.expectStatus().isCreated();
	}

	@Test
	void whoamiAccessMatrix() {
		webTestClient.get().uri("/api/user/whoami").exchange().expectStatus().isUnauthorized();
		var user = login("fuu", "BarbarossA123");
		webTestClient.get().uri("/api/user/whoami")
			.cookie("JSESSIONID", user.sessionId())
			.exchange()
			.expectStatus().isOk();
		webTestClient.get().uri("/api/user/whoami")
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.exchange()
			.expectStatus().isOk();
		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient.get().uri("/api/user/whoami")
			.cookie("JSESSIONID", admin.sessionId())
			.exchange()
			.expectStatus().isOk();
		webTestClient.get().uri("/api/user/whoami")
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void adminAccessMatrix() {
		webTestClient.get().uri("/api/admin/users").exchange().expectStatus().isUnauthorized();
		var user = login("fuu", "BarbarossA123");
		webTestClient.get().uri("/api/admin/users")
			.cookie("JSESSIONID", user.sessionId())
			.exchange()
			.expectStatus().isForbidden();
		webTestClient.get().uri("/api/admin/users")
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.exchange()
			.expectStatus().isForbidden();
		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient.get().uri("/api/admin/users")
			.cookie("JSESSIONID", admin.sessionId())
			.exchange()
			.expectStatus().isOk();
		webTestClient.get().uri("/api/admin/users")
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void actuatorHealthAccessMatrix() {
		webTestClient.get().uri("/actuator/health")
			.exchange()
			.expectStatus().isOk()
			.expectBody()
			.jsonPath("$.status").isEqualTo("UP")
			.jsonPath("$.components").doesNotExist();
		var user = login("fuu", "BarbarossA123");
		webTestClient.get().uri("/actuator/health")
			.cookie("JSESSIONID", user.sessionId())
			.exchange()
			.expectStatus().isOk();
		webTestClient.get().uri("/actuator/health")
			.cookie("JSESSIONID", user.sessionId())
			.cookie("XSRF-TOKEN", user.csrfToken())
			.header("X-XSRF-TOKEN", user.csrfToken())
			.exchange()
			.expectStatus().isOk();
		var admin = login("admin", "Sup3rSecretAdmin");
		webTestClient
			.get()
			.uri("/actuator/health")
			.cookie("JSESSIONID", admin.sessionId())
			.exchange()
			.expectStatus().isOk();
		webTestClient.get().uri("/actuator/health")
			.cookie("JSESSIONID", admin.sessionId())
			.cookie("XSRF-TOKEN", admin.csrfToken())
			.header("X-XSRF-TOKEN", admin.csrfToken())
			.exchange()
			.expectStatus().isOk();
	}

	private AuthSession login(String username, String password) {
		var csrf = fetchCsrfToken();
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("username", username);
		form.add("password", password);

		var loginResult = webTestClient.post()
			.uri("/login")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.cookie("XSRF-TOKEN", csrf)
			.header("X-XSRF-TOKEN", csrf)
			.bodyValue(form)
			.exchange()
			.expectStatus().isOk()
			.returnResult(String.class);

		String sessionId = extractCookie(loginResult.getResponseHeaders(), "JSESSIONID");
		String latestCsrf = extractCookie(loginResult.getResponseHeaders(), "XSRF-TOKEN");
		return new AuthSession(sessionId, latestCsrf == null ? csrf : latestCsrf);
	}

	private String fetchCsrfToken() {
		var result = webTestClient.get().uri("/").exchange().expectStatus().isOk().returnResult(String.class);
		String token = extractCookie(result.getResponseHeaders(), "XSRF-TOKEN");
		assertThat(token).isNotBlank();
		return token;
	}

	private String extractCookie(HttpHeaders headers, String name) {
		for (String value : headers.getOrEmpty(HttpHeaders.SET_COOKIE)) {
			if (value.startsWith(name + "=")) {
				String firstSegment = value.split(";", 2)[0];
				return firstSegment.substring((name + "=").length());
			}
		}
		return null;
	}

	private record AuthSession(String sessionId, String csrfToken) {
	}
}
