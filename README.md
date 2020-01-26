# Google Login Authentication
Google Login Authentication using Spring Boot and Spring Security

## Technology Stack
* Maven
* Spring Boot
* Spring JPA
* Spring Web
* Spring Security
* Oauth2 Authentication
* PostgreSQL

## PostgreSQL Schema
* create table oauth_access_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication bytea,
  refresh_token VARCHAR(256)
);

* create table oauth_refresh_token (
  token_id VARCHAR(256),
  token bytea,
  authentication bytea
);
