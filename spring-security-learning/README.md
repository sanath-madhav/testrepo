# Spring Security Learning — Basic to Advanced

A comprehensive multi-module Maven project covering every major concept in Spring Security, from basic in-memory authentication to JWT, OAuth2, and method-level security.

---

## Table of Contents

1. [Architecture Overview (HLD)](#1-architecture-overview-hld)
2. [Spring Security Filter Chain (Core Internals)](#2-spring-security-filter-chain-core-internals)
3. [Authentication Architecture (Class Diagram)](#3-authentication-architecture-class-diagram)
4. [Module 1 — Basic Security](#4-module-1--basic-security)
5. [Module 2 — JDBC Authentication & Custom UserDetailsService](#5-module-2--jdbc-authentication--custom-userdetailsservice)
6. [Module 3 — JWT Authentication](#6-module-3--jwt-authentication)
7. [Module 4 — OAuth2 / OpenID Connect](#7-module-4--oauth2--openid-connect)
8. [Module 5 — Method Security, CORS, Exception Handling](#8-module-5--method-security-cors-exception-handling)
9. [Security State Diagram](#9-security-state-diagram)
10. [CSRF Protection](#10-csrf-protection)
11. [Password Encoding](#11-password-encoding)
12. [Quick Reference](#12-quick-reference)
13. [Running Each Module](#13-running-each-module)

---

## 1. Architecture Overview (HLD)

Spring Security works as a **servlet filter chain** that wraps the entire Spring MVC application.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        HIGH-LEVEL ARCHITECTURE                                │
│                                                                               │
│  ┌─────────┐     ┌──────────────────────────────────────────────┐            │
│  │ Client  │────▶│           SECURITY FILTER CHAIN              │            │
│  │(Browser │     │  ┌────────────────────────────────────────┐  │            │
│  │  / App) │     │  │  SecurityContextPersistenceFilter      │  │            │
│  └─────────┘     │  │  (loads/saves SecurityContext)         │  │            │
│       │          │  ├────────────────────────────────────────┤  │            │
│       │          │  │  UsernamePasswordAuthenticationFilter  │  │            │
│       │          │  │  (handles form login POST)             │  │            │
│       │          │  ├────────────────────────────────────────┤  │            │
│       │          │  │  BearerTokenAuthenticationFilter       │  │            │
│       │          │  │  (handles JWT Bearer tokens)           │  │            │
│       │          │  ├────────────────────────────────────────┤  │            │
│       │          │  │  BasicAuthenticationFilter             │  │            │
│       │          │  │  (handles HTTP Basic auth)             │  │            │
│       │          │  ├────────────────────────────────────────┤  │            │
│       │          │  │  ExceptionTranslationFilter            │  │            │
│       │          │  │  (converts security exceptions to      │  │            │
│       │          │  │   401/403 responses)                   │  │            │
│       │          │  ├────────────────────────────────────────┤  │            │
│       │          │  │  FilterSecurityInterceptor             │  │            │
│       │          │  │  (authorizes each request)             │  │            │
│       │          │  └────────────────────────────────────────┘  │            │
│       │          └─────────────────┬────────────────────────────┘            │
│       │                            │                                          │
│       │                  ┌─────────▼──────────┐                              │
│       │                  │   DispatcherServlet │                              │
│       │                  │   (Spring MVC)      │                              │
│       │                  └─────────┬──────────┘                              │
│       │                            │                                          │
│       │              ┌─────────────▼──────────────┐                          │
│       │              │     @RestController /       │                          │
│       │              │     @Controller methods     │                          │
│       │              │  @PreAuthorize("hasRole")   │ ◀── Method Security     │
│       │              └────────────────────────────┘                          │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     SECURITY COMPONENTS                                  │ │
│  │                                                                          │ │
│  │  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────────────┐ │ │
│  │  │ AuthManager      │  │ UserDetailsService│  │  PasswordEncoder      │ │ │
│  │  │ (orchestrates)   │  │ (loads users)    │  │  (BCrypt/Argon2)      │ │ │
│  │  └──────────────────┘  └─────────────────┘  └────────────────────────┘ │ │
│  │                                                                          │ │
│  │  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────────────┐ │ │
│  │  │ SecurityContext  │  │ Authentication   │  │  GrantedAuthority     │ │ │
│  │  │ Holder           │  │ (principal +     │  │  (roles/permissions)  │ │ │
│  │  │ (ThreadLocal)    │  │  authorities)    │  │                       │ │ │
│  │  └──────────────────┘  └─────────────────┘  └────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Spring Security Filter Chain (Core Internals)

```mermaid
flowchart TD
    A[HTTP Request] --> B[DelegatingFilterProxy\nBridge: Servlet Filter → Spring Bean]
    B --> C[FilterChainProxy\nManages SecurityFilterChain list]
    C --> D{Which chain\nmatches request?}
    D -->|/api/** - REST| E[SecurityFilterChain REST]
    D -->|/** - Web| F[SecurityFilterChain Web]

    E --> G[SecurityContextHolderFilter\nSet up SecurityContext for request]
    G --> H[CsrfFilter\nValidate CSRF token]
    H --> I[UsernamePasswordAuthFilter\nForm login POST /login]
    I --> J[BasicAuthenticationFilter\nHTTP Basic auth header]
    J --> K[BearerTokenAuthFilter\nJWT Authorization: Bearer]
    K --> L[ExceptionTranslationFilter\nCatch AuthException, AccessDeniedException]
    L --> M[AuthorizationFilter\nCheck if request is authorized]
    M --> N[DispatcherServlet]
    N --> O[@Controller / @RestController]

    style A fill:#e1f5fe
    style O fill:#e8f5e9
    style D fill:#fff9c4
```

### Key Insight: Filter Order Matters

Filters are evaluated **in order, top to bottom**. The first filter that handles the request (e.g., JWT filter) sets the `Authentication` in the `SecurityContext`. Later filters see the already-populated context.

---

## 3. Authentication Architecture (Class Diagram)

```mermaid
classDiagram
    class SecurityContextHolder {
        -SecurityContext context
        +getContext() SecurityContext
        +setContext(SecurityContext)
        +clearContext()
        <<static utility>>
    }

    class SecurityContext {
        +getAuthentication() Authentication
        +setAuthentication(Authentication)
    }

    class Authentication {
        <<interface>>
        +getPrincipal() Object
        +getCredentials() Object
        +getAuthorities() Collection~GrantedAuthority~
        +isAuthenticated() boolean
        +getName() String
    }

    class UsernamePasswordAuthenticationToken {
        -Object principal
        -Object credentials
        +UsernamePasswordAuthenticationToken(principal, creds)
        +UsernamePasswordAuthenticationToken(principal, creds, authorities)
    }

    class JwtAuthenticationToken {
        -Jwt jwt
        +JwtAuthenticationToken(jwt, authorities)
    }

    class OAuth2AuthenticationToken {
        -OAuth2User principal
        -String authorizedClientRegistrationId
    }

    class AuthenticationManager {
        <<interface>>
        +authenticate(Authentication) Authentication
    }

    class ProviderManager {
        -List~AuthenticationProvider~ providers
        +authenticate(Authentication) Authentication
    }

    class AuthenticationProvider {
        <<interface>>
        +authenticate(Authentication) Authentication
        +supports(Class) boolean
    }

    class DaoAuthenticationProvider {
        -UserDetailsService userDetailsService
        -PasswordEncoder passwordEncoder
        +authenticate(Authentication) Authentication
    }

    class UserDetailsService {
        <<interface>>
        +loadUserByUsername(String) UserDetails
    }

    class UserDetails {
        <<interface>>
        +getUsername() String
        +getPassword() String
        +getAuthorities() Collection~GrantedAuthority~
        +isEnabled() boolean
        +isAccountNonExpired() boolean
        +isAccountNonLocked() boolean
        +isCredentialsNonExpired() boolean
    }

    class PasswordEncoder {
        <<interface>>
        +encode(rawPassword) String
        +matches(rawPassword, encoded) boolean
    }

    class BCryptPasswordEncoder {
        -int strength
        +encode(rawPassword) String
        +matches(rawPassword, encoded) boolean
    }

    class GrantedAuthority {
        <<interface>>
        +getAuthority() String
    }

    class SimpleGrantedAuthority {
        -String role
        +getAuthority() String
    }

    SecurityContextHolder "1" --> "1" SecurityContext
    SecurityContext "1" --> "0..1" Authentication
    Authentication <|.. UsernamePasswordAuthenticationToken
    Authentication <|.. JwtAuthenticationToken
    Authentication <|.. OAuth2AuthenticationToken
    AuthenticationManager <|.. ProviderManager
    ProviderManager "1" --> "*" AuthenticationProvider
    AuthenticationProvider <|.. DaoAuthenticationProvider
    DaoAuthenticationProvider --> UserDetailsService
    DaoAuthenticationProvider --> PasswordEncoder
    PasswordEncoder <|.. BCryptPasswordEncoder
    Authentication --> "*" GrantedAuthority
    GrantedAuthority <|.. SimpleGrantedAuthority
    UserDetailsService ..> UserDetails : returns
```

---

## 4. Module 1 — Basic Security

**Location:** `module1-basic-security/` | **Port:** `8081`

### Concepts Covered
- In-Memory Authentication (`InMemoryUserDetailsManager`)
- Form-Based Login with custom login page
- HTTP Basic Authentication
- Role-based access control in `SecurityFilterChain`
- Remember-Me authentication
- Thymeleaf `sec:authorize` tags

### Sequence Diagram — Form Login

```mermaid
sequenceDiagram
    participant Browser
    participant UsernamePasswordFilter as UsernamePasswordAuthenticationFilter
    participant AuthManager as AuthenticationManager (ProviderManager)
    participant Provider as DaoAuthenticationProvider
    participant UDS as InMemoryUserDetailsManager
    participant PasswordEncoder as BCryptPasswordEncoder
    participant SecurityContext as SecurityContextHolder
    participant Session

    Browser->>UsernamePasswordFilter: POST /login {username, password}
    UsernamePasswordFilter->>UsernamePasswordFilter: Extract credentials
    UsernamePasswordFilter->>AuthManager: authenticate(UnauthedToken)
    AuthManager->>Provider: authenticate(UnauthedToken)
    Provider->>UDS: loadUserByUsername("user")
    UDS-->>Provider: UserDetails {username, BCrypt(pass), roles}
    Provider->>PasswordEncoder: matches("password", "$2a$12$...")
    PasswordEncoder-->>Provider: true
    Provider->>Provider: Check account status flags
    Provider-->>AuthManager: AuthenticatedToken(UserDetails, authorities)
    AuthManager-->>UsernamePasswordFilter: AuthenticatedToken
    UsernamePasswordFilter->>SecurityContext: setAuthentication(AuthenticatedToken)
    UsernamePasswordFilter->>Session: Store SecurityContext in session
    UsernamePasswordFilter-->>Browser: 302 Redirect /dashboard
    Browser->>Browser: Follow redirect GET /dashboard
    Browser->>Session: Send session cookie (JSESSIONID)
    Session-->>SecurityContext: Load SecurityContext from session
    SecurityContext-->>Browser: 200 /dashboard (rendered with user info)
```

### Sequence Diagram — HTTP Basic

```mermaid
sequenceDiagram
    participant Client
    participant BasicFilter as BasicAuthenticationFilter
    participant AuthManager
    participant UDS as UserDetailsService
    participant SecurityContext

    Client->>BasicFilter: GET /api/user\nAuthorization: Basic dXNlcjpwYXNzd29yZA==
    BasicFilter->>BasicFilter: Base64 decode → "user:password"
    BasicFilter->>AuthManager: authenticate(UnauthedToken("user","password"))
    AuthManager->>UDS: loadUserByUsername("user")
    UDS-->>AuthManager: UserDetails
    AuthManager-->>BasicFilter: AuthenticatedToken
    BasicFilter->>SecurityContext: setAuthentication(token)
    BasicFilter-->>Client: 200 OK + response body

    Note over Client,SecurityContext: No session created! Client must send\nAuthorization header on EVERY request.

    Client->>BasicFilter: GET /api/admin\nAuthorization: Basic dXNlcjpwYXNzd29yZA==
    BasicFilter->>AuthManager: authenticate() [again, stateless]
    AuthManager-->>BasicFilter: AuthenticatedToken (ROLE_USER only)
    BasicFilter->>SecurityContext: setAuthentication
    SecurityContext-->>Client: 403 Forbidden (needs ROLE_ADMIN)
```

### Key Configuration Differences

| Feature | Form Login | HTTP Basic |
|--------|-----------|------------|
| Authentication mechanism | POST /login form | Authorization: Basic header |
| Session | Stateful (JSESSIONID) | Stateless |
| Logout | POST /logout | N/A (clear credentials) |
| Browser dialog | Custom HTML page | Native browser dialog |
| CSRF protection | Required | Not needed (stateless) |
| Use case | Web applications | REST APIs, microservices |

---

## 5. Module 2 — JDBC Authentication & Custom UserDetailsService

**Location:** `module2-jdbc-auth/` | **Port:** `8082`

### Concepts Covered
- Custom `UserDetailsService` with JPA/H2
- `DaoAuthenticationProvider` wiring
- Password encoding on registration
- `AuthenticationManager` bean exposure
- Role hierarchy via many-to-many relationship

### LLD — UserDetailsService Flow

```mermaid
classDiagram
    class CustomUserDetailsService {
        -UserRepository userRepository
        +loadUserByUsername(String) UserDetails
        -mapRolesToAuthorities(Set~Role~) Set~GrantedAuthority~
    }

    class AppUser {
        -Long id
        -String username
        -String password  ← BCrypt hash in DB
        -Set~Role~ roles
        -boolean enabled
        -boolean accountNonExpired
        -boolean accountNonLocked
        -boolean credentialsNonExpired
    }

    class Role {
        -Long id
        -String name  ← "ROLE_USER", "ROLE_ADMIN"
    }

    class UserRepository {
        <<JpaRepository>>
        +findByUsername(String) Optional~AppUser~
        +existsByUsername(String) boolean
    }

    class UserDetails {
        <<Spring Security Interface>>
        +getUsername() String
        +getPassword() String
        +getAuthorities() Collection
        +isEnabled() boolean
        +isAccountNonExpired() boolean
        +isAccountNonLocked() boolean
        +isCredentialsNonExpired() boolean
    }

    class SimpleGrantedAuthority {
        -String authority  ← "ROLE_USER"
    }

    CustomUserDetailsService --> UserRepository
    UserRepository ..> AppUser : loads
    AppUser "1" --> "*" Role : has
    CustomUserDetailsService ..> UserDetails : returns
    UserDetails --> SimpleGrantedAuthority
```

### Database Schema

```
app_users                    user_roles               roles
─────────────────────        ─────────────            ──────────────────
id          BIGINT PK        user_id BIGINT FK   →   id    BIGINT PK
username    VARCHAR UNIQUE   role_id BIGINT FK        name  VARCHAR UNIQUE
password    VARCHAR          (many-to-many join)      (ROLE_USER, ROLE_ADMIN)
enabled     BOOLEAN
account_non_expired  BOOL
account_non_locked   BOOL
credentials_non_expired BOOL
```

### Sequence Diagram — JDBC Authentication

```mermaid
sequenceDiagram
    participant Client
    participant SecurityFilter as BasicAuthenticationFilter
    participant AuthManager as ProviderManager
    participant Provider as DaoAuthenticationProvider
    participant CUDS as CustomUserDetailsService
    participant Repo as UserRepository
    participant DB as H2 Database
    participant PE as BCryptPasswordEncoder

    Client->>SecurityFilter: GET /api/profile\nAuthorization: Basic ZGJ1c2VyOnBhc3N3b3Jk
    SecurityFilter->>AuthManager: authenticate(UnauthedToken)
    AuthManager->>Provider: authenticate(UnauthedToken)
    Provider->>CUDS: loadUserByUsername("dbuser")
    CUDS->>Repo: findByUsername("dbuser")
    Repo->>DB: SELECT * FROM app_users\nJOIN user_roles JOIN roles\nWHERE username = 'dbuser'
    DB-->>Repo: AppUser{..., roles=[ROLE_USER]}
    Repo-->>CUDS: Optional<AppUser>
    CUDS->>CUDS: mapRolesToAuthorities([ROLE_USER])
    CUDS-->>Provider: UserDetails{username, BCryptHash, [ROLE_USER]}
    Provider->>PE: matches("password", "$2a$12$abc...")
    PE-->>Provider: true
    Provider-->>AuthManager: AuthenticatedToken([ROLE_USER])
    AuthManager-->>SecurityFilter: AuthenticatedToken
    SecurityFilter-->>Client: 200 OK {username: "dbuser", authorities: [ROLE_USER]}
```

---

## 6. Module 3 — JWT Authentication

**Location:** `module3-jwt-auth/` | **Port:** `8083`

### Concepts Covered
- JWT structure, signing, and validation
- Custom `JwtAuthenticationFilter` (OncePerRequestFilter)
- Stateless session management
- Access token + refresh token pattern
- CSRF disabled rationale for JWT APIs

### JWT Token Structure

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9    <- HEADER (Base64URL)
.
eyJzdWIiOiJqd3R1c2VyIiwiaWF0IjoxNzEwMDAwMDAwLCJleHAiOjE3MTAwODY0MDAsInJvbGVzIjpbIlJPTEVfVVNFUiJdfQ==
                                           <- PAYLOAD (Base64URL)
.
HMACSHA256(header + "." + payload, secret) <- SIGNATURE (not Base64)

HEADER decoded:   { "alg": "HS256", "typ": "JWT" }
PAYLOAD decoded:  {
                    "sub": "jwtuser",
                    "iat": 1710000000,
                    "exp": 1710086400,
                    "roles": ["ROLE_USER"]
                  }
```

### Sequence Diagram — JWT Login + Protected API Call

```mermaid
sequenceDiagram
    participant Client
    participant AuthController as POST /auth/login
    participant AuthManager as AuthenticationManager
    participant DaoProvider as DaoAuthenticationProvider
    participant UDS as JwtUserDetailsService
    participant JwtUtil
    participant JwtFilter as JwtAuthenticationFilter
    participant SecurityCtx as SecurityContext
    participant API as GET /api/profile

    rect rgb(220, 240, 255)
        Note over Client,JwtUtil: STEP 1: Login and get JWT
        Client->>AuthController: POST /auth/login\n{"username":"jwtuser","password":"password"}
        AuthController->>AuthManager: authenticate(UnauthedToken)
        AuthManager->>DaoProvider: authenticate
        DaoProvider->>UDS: loadUserByUsername("jwtuser")
        UDS-->>DaoProvider: UserDetails
        DaoProvider-->>AuthManager: AuthenticatedToken
        AuthManager-->>AuthController: Authentication
        AuthController->>JwtUtil: generateToken(userDetails)
        JwtUtil->>JwtUtil: Build JWT:\n- subject: "jwtuser"\n- roles claim\n- issued at, expiry\n- sign with HS256
        JwtUtil-->>AuthController: "eyJhbGci..."
        AuthController-->>Client: 200 OK\n{accessToken, refreshToken, tokenType:"Bearer"}
    end

    rect rgb(220, 255, 220)
        Note over Client,API: STEP 2: Access protected resource
        Client->>JwtFilter: GET /api/profile\nAuthorization: Bearer eyJhbGci...
        JwtFilter->>JwtFilter: Extract JWT from "Bearer " header
        JwtFilter->>JwtUtil: extractUsername(jwt)
        JwtUtil->>JwtUtil: Parse & verify HMAC signature
        JwtUtil-->>JwtFilter: "jwtuser"
        JwtFilter->>SecurityCtx: getAuthentication() == null?
        SecurityCtx-->>JwtFilter: null (not authenticated yet)
        JwtFilter->>UDS: loadUserByUsername("jwtuser")
        UDS-->>JwtFilter: UserDetails
        JwtFilter->>JwtUtil: validateToken(jwt, userDetails)
        JwtUtil->>JwtUtil: username matches + not expired
        JwtUtil-->>JwtFilter: true
        JwtFilter->>JwtFilter: Create AuthenticatedToken(userDetails, authorities)
        JwtFilter->>SecurityCtx: setAuthentication(AuthenticatedToken)
        JwtFilter->>API: Continue filter chain
        API-->>Client: 200 OK {username: "jwtuser", authorities: [...]}
    end
```

### Sequence Diagram — Invalid / Expired JWT

```mermaid
sequenceDiagram
    participant Client
    participant JwtFilter as JwtAuthenticationFilter
    participant SecurityCtx as SecurityContext
    participant AuthzFilter as AuthorizationFilter
    participant EntryPoint as AuthenticationEntryPoint

    Client->>JwtFilter: GET /api/profile\nAuthorization: Bearer expired.token.here
    JwtFilter->>JwtFilter: extractUsername(token)
    JwtFilter->>JwtFilter: isTokenExpired() → true
    JwtFilter->>JwtFilter: Validation failed, do not set Authentication
    JwtFilter->>AuthzFilter: Continue chain WITHOUT setting SecurityContext
    AuthzFilter->>SecurityCtx: getAuthentication()
    SecurityCtx-->>AuthzFilter: AnonymousAuthenticationToken
    AuthzFilter->>AuthzFilter: anyRequest().authenticated()\nAnonymous user fails this check
    AuthzFilter->>EntryPoint: commence(request, AuthenticationException)
    EntryPoint-->>Client: 401 Unauthorized\n{"error": "Authentication required"}
```

### LLD — JWT Component Diagram

```mermaid
classDiagram
    class JwtUtil {
        -String secretKey
        -long jwtExpirationMs
        -long refreshExpirationMs
        +generateToken(UserDetails) String
        +generateRefreshToken(UserDetails) String
        +validateToken(String, UserDetails) boolean
        +extractUsername(String) String
        +extractExpiration(String) Date
        +isTokenExpired(String) boolean
        -getSigningKey() SecretKey
        -buildToken(claims, userDetails, expiry) String
        -extractAllClaims(String) Claims
    }

    class JwtAuthenticationFilter {
        -JwtUtil jwtUtil
        -UserDetailsService userDetailsService
        +doFilterInternal(request, response, chain)
        <<OncePerRequestFilter>>
    }

    class AuthController {
        -AuthenticationManager authManager
        -JwtUtil jwtUtil
        +login(LoginRequest) ResponseEntity
        +refresh(RefreshRequest) ResponseEntity
    }

    class SecurityConfig {
        -JwtAuthenticationFilter jwtFilter
        +securityFilterChain(HttpSecurity) SecurityFilterChain
        +authenticationManager(config) AuthenticationManager
        -STATELESS session policy
        -addFilterBefore(JwtFilter, UsernamePasswordFilter)
    }

    JwtAuthenticationFilter --> JwtUtil
    JwtAuthenticationFilter --> UserDetailsService
    AuthController --> JwtUtil
    AuthController --> AuthenticationManager
    SecurityConfig --> JwtAuthenticationFilter
```

### Token Lifecycle State Diagram

```mermaid
stateDiagram-v2
    [*] --> NotIssued
    NotIssued --> Active: POST /auth/login\n(valid credentials)
    Active --> Active: Valid request with token\n(not expired, signature valid)
    Active --> Expired: time > exp claim
    Active --> Revoked: logout / token blacklist
    Expired --> Active: POST /auth/refresh\n(valid refresh token)
    Expired --> [*]: refresh token also expired
    Revoked --> [*]: cannot be used again
    Active --> Invalid: tampered / wrong signature
    Invalid --> [*]: rejected by server

    note right of Active
        Token validated on every request
        No server-side session storage
        Payload visible (Base64), not encrypted
    end note
```

---

## 7. Module 4 — OAuth2 / OpenID Connect

**Location:** `module4-oauth2/` | **Port:** `8084`

### Concepts Covered
- OAuth2 Authorization Code Flow
- OpenID Connect (OIDC) identity layer
- `CustomOAuth2UserService` for user attribute mapping
- Multiple provider configuration (Google, GitHub)
- OAuth2 access token usage for API calls

### OAuth2 Authorization Code Flow

```mermaid
sequenceDiagram
    participant User as User (Browser)
    participant App as Spring Boot App\n(OAuth2 Client)
    participant AuthServer as Authorization Server\n(Google/GitHub)
    participant ResourceServer as Resource Server\n(Provider APIs)

    User->>App: GET /dashboard (unauthenticated)
    App-->>User: 302 Redirect /login
    User->>App: GET /login — click "Login with Google"
    App-->>User: 302 Redirect to Google\n/oauth2/authorization/google
    Note over App,AuthServer: Spring generates URL:\nhttps://accounts.google.com/o/oauth2/auth\n?client_id=...&redirect_uri=...&scope=openid email profile\n&response_type=code&state=csrf_random_value

    User->>AuthServer: GET /o/oauth2/auth?code_request...
    AuthServer-->>User: Show consent screen\n"Allow SpringApp to access your profile?"
    User->>AuthServer: User approves
    AuthServer-->>User: 302 Redirect to App\n/login/oauth2/code/google?code=auth_code&state=csrf_value

    User->>App: GET /login/oauth2/code/google?code=...&state=...
    App->>App: Verify state matches (CSRF protection)
    App->>AuthServer: POST /token\n{code, client_id, client_secret, redirect_uri, grant_type=authorization_code}
    Note over App,AuthServer: Server-to-server exchange!\nClient secret never sent to browser
    AuthServer-->>App: {access_token, id_token (JWT), refresh_token}
    App->>App: Validate id_token signature
    App->>AuthServer: GET /userinfo\nAuthorization: Bearer access_token
    AuthServer-->>App: {sub, name, email, picture, ...}
    App->>App: CustomOAuth2UserService.loadUser()\nMap provider user to local roles
    App->>App: Create session, set SecurityContext
    App-->>User: 302 Redirect /dashboard
    User->>App: GET /dashboard (with session cookie)
    App-->>User: 200 OK — Dashboard with user info
```

### OAuth2 Key Concepts

```
┌────────────────────────────────────────────────────────────────┐
│                    OAuth2 GRANT TYPES                          │
│                                                                │
│  Authorization Code  ← WEB APPS (this module)                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 1. Redirect to Auth Server with code_challenge (PKCE)    │  │
│  │ 2. User authenticates on Auth Server                     │  │
│  │ 3. Auth Server redirects back with authorization code    │  │
│  │ 4. Server exchanges code for tokens (secret stays safe)  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  Client Credentials ← MACHINE-TO-MACHINE (no user)           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 1. Client sends client_id + client_secret directly       │  │
│  │ 2. Gets access token immediately                         │  │
│  │ Use: background services, microservice-to-microservice   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  Resource Owner Password ← DEPRECATED (avoid)                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ User sends username/password to client directly          │  │
│  │ Client exchanges for token (defeats purpose of OAuth2)   │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│               OAuth2 vs OpenID Connect (OIDC)                  │
│                                                                │
│  OAuth2: "Can I access your Google Drive?" (AUTHORIZATION)    │
│  OIDC:   "Who are you?" (AUTHENTICATION)                      │
│                                                                │
│  OIDC adds:                                                    │
│  • id_token (JWT) with user identity claims                   │
│  • Standardized /userinfo endpoint                            │
│  • Standard claims: sub, name, email, picture, ...            │
│  • UserInfo endpoint for additional claims                    │
└────────────────────────────────────────────────────────────────┘
```

### OAuth2 Class Diagram

```mermaid
classDiagram
    class OAuth2SecurityConfig {
        -CustomOAuth2UserService oAuth2UserService
        +securityFilterChain(HttpSecurity) SecurityFilterChain
        -oauth2Login configuration
        -userInfoEndpoint configuration
    }

    class CustomOAuth2UserService {
        -DefaultOAuth2UserService delegate
        +loadUser(OAuth2UserRequest) OAuth2User
        -mapAuthorities(provider, attributes) Set~GrantedAuthority~
    }

    class OAuth2User {
        <<interface>>
        +getAttributes() Map~String,Object~
        +getAuthorities() Collection~GrantedAuthority~
        +getName() String
    }

    class DefaultOAuth2User {
        -Map attributes
        -String nameAttributeKey
        -Set authorities
    }

    class ClientRegistration {
        -String registrationId (google/github)
        -String clientId
        -String clientSecret
        -String redirectUri
        -Set scopes
        -ProviderDetails providerDetails
    }

    class OAuth2AuthorizedClient {
        -ClientRegistration clientRegistration
        -String principalName
        -OAuth2AccessToken accessToken
        -OAuth2RefreshToken refreshToken
    }

    CustomOAuth2UserService --> DefaultOAuth2UserService : delegates
    DefaultOAuth2UserService ..> OAuth2User : returns
    OAuth2User <|.. DefaultOAuth2User
    OAuth2SecurityConfig --> CustomOAuth2UserService
    OAuth2AuthorizedClient --> ClientRegistration
```

---

## 8. Module 5 — Method Security, CORS, Exception Handling

**Location:** `module5-method-security/` | **Port:** `8085`

### Concepts Covered
- `@PreAuthorize` / `@PostAuthorize` with SpEL
- `@PreFilter` / `@PostFilter` for collection filtering
- `@Secured` (role-based)
- `@RolesAllowed` (JSR-250)
- Custom `PermissionEvaluator` with `hasPermission()`
- CORS configuration
- Security exception handling (401 vs 403)

### Method Security — How AOP Works

```mermaid
sequenceDiagram
    participant Controller
    participant Proxy as Spring AOP Proxy\n(wraps DocumentService bean)
    participant Interceptor as MethodSecurityInterceptor
    participant ExprEval as MethodSecurityExpressionHandler
    participant SpEL as SpEL Expression Engine
    participant Service as DocumentService (target)
    participant SecCtx as SecurityContext

    Controller->>Proxy: documentService.getAllDocuments()
    Note over Proxy: Proxy intercepts! Target not called yet
    Proxy->>Interceptor: invoke(MethodInvocation)
    Interceptor->>ExprEval: createEvaluationContext(authentication, method, args)
    ExprEval->>SecCtx: getContext().getAuthentication()
    SecCtx-->>ExprEval: Authentication (roles, etc.)
    Interceptor->>SpEL: evaluate("hasRole('ADMIN')", context)

    alt authentication has ROLE_ADMIN
        SpEL-->>Interceptor: true
        Interceptor->>Service: proceed() — call real method
        Service-->>Interceptor: List<Document>
        Interceptor-->>Proxy: List<Document>
        Proxy-->>Controller: List<Document>
    else missing ROLE_ADMIN
        SpEL-->>Interceptor: false
        Interceptor-->>Proxy: throw AccessDeniedException
        Proxy-->>Controller: throw AccessDeniedException
        Controller-->>Controller: @ExceptionHandler catches → 403 JSON
    end
```

### Method Security Annotations Comparison

```
┌─────────────────────────────────────────────────────────────────────────┐
│              METHOD SECURITY ANNOTATIONS — COMPARISON                    │
├────────────────┬──────────────┬────────────────┬────────────────────────┤
│ Annotation     │ When Checked │ Supports SpEL  │ Use Case               │
├────────────────┼──────────────┼────────────────┼────────────────────────┤
│ @PreAuthorize  │ Before call  │ Yes (full)     │ Primary recommendation │
│ @PostAuthorize │ After call   │ Yes (returnObj)│ Check return value     │
│ @PreFilter     │ Before call  │ Yes (filterObj)│ Filter input collection│
│ @PostFilter    │ After call   │ Yes (filterObj)│ Filter output list     │
│ @Secured       │ Before call  │ No             │ Simple role checks     │
│ @RolesAllowed  │ Before call  │ No             │ JSR-250 standard       │
└────────────────┴──────────────┴────────────────┴────────────────────────┘

SpEL Quick Reference:
  hasRole('ADMIN')                 → checks ROLE_ADMIN
  hasAnyRole('ADMIN','MANAGER')    → checks any of the roles
  hasAuthority('READ')             → exact authority match
  isAuthenticated()                → any logged-in user
  isAnonymous()                    → not logged in
  #paramName                       → method parameter value
  authentication.name              → current username
  returnObject.owner               → property of return value (@PostAuthorize)
  filterObject.owner               → element in collection (@Pre/PostFilter)
  @beanName.method(authentication) → call a Spring bean
```

### CORS Flow Diagram

```mermaid
sequenceDiagram
    participant Browser
    participant CorsFilter as CorsFilter (Spring)
    participant API as REST API

    Note over Browser,API: Case 1: Simple same-origin request — no CORS involved
    Browser->>API: GET /api/data (same origin)
    API-->>Browser: 200 OK

    Note over Browser,API: Case 2: Cross-origin simple request
    Browser->>CorsFilter: GET /api/data\nOrigin: http://localhost:3000
    CorsFilter->>CorsFilter: Check allowed origins list
    CorsFilter->>API: Forward request
    API-->>CorsFilter: 200 OK + data
    CorsFilter-->>Browser: 200 OK + data\nAccess-Control-Allow-Origin: http://localhost:3000

    Note over Browser,API: Case 3: Preflight for complex request (PUT, custom headers)
    Browser->>CorsFilter: OPTIONS /api/data\nOrigin: http://localhost:3000\nAccess-Control-Request-Method: PUT\nAccess-Control-Request-Headers: Authorization
    CorsFilter->>CorsFilter: Validate preflight against config
    CorsFilter-->>Browser: 200 OK\nAccess-Control-Allow-Origin: http://localhost:3000\nAccess-Control-Allow-Methods: GET,POST,PUT,DELETE\nAccess-Control-Allow-Headers: Authorization,Content-Type\nAccess-Control-Max-Age: 3600

    Browser->>CorsFilter: PUT /api/data\nOrigin: http://localhost:3000\nAuthorization: Bearer jwt...
    CorsFilter->>API: Forward (origin validated)
    API-->>Browser: 200 OK + Access-Control-Allow-Origin header
```

### Security Exception Flow

```mermaid
flowchart TD
    A[Incoming Request] --> B[SecurityFilterChain]
    B --> C{Authenticated?}
    C -->|No| D[ExceptionTranslationFilter\ncatches AuthenticationException]
    C -->|Yes| E{Authorized?}
    E -->|No| F[ExceptionTranslationFilter\ncatches AccessDeniedException]
    E -->|Yes| G[Request proceeds to Controller]

    D --> H{Request type?}
    H -->|Web/HTML| I[Redirect to /login\n302 Found]
    H -->|REST API| J[AuthenticationEntryPoint\n401 Unauthorized JSON]

    F --> K{Request type?}
    K -->|Web/HTML| L[Redirect to /403\n403 Forbidden page]
    K -->|REST API| M[AccessDeniedHandler\n403 Forbidden JSON]

    G --> N{Method security?}
    N -->|@PreAuthorize fails| O[AccessDeniedException\n@ExceptionHandler catches]
    N -->|Passes| P[Method executes]
    O --> M

    style D fill:#ffecb3
    style F fill:#ffcdd2
    style J fill:#ef9a9a
    style M fill:#ef9a9a
    style P fill:#c8e6c9
```

---

## 9. Security State Diagram

Full security lifecycle for a user session:

```mermaid
stateDiagram-v2
    [*] --> Anonymous: Request arrives\nno credentials

    Anonymous --> Authenticating: Submits credentials\n(form/basic/jwt/oauth2)

    Authenticating --> Authenticated: Credentials valid\nAuthenticatedToken in SecurityContext
    Authenticating --> AuthenticationFailed: Bad credentials\nUsernameNotFoundException\nBadCredentialsException
    Authenticating --> AccountLocked: Account locked/disabled\nLockedException\nDisabledException

    AuthenticationFailed --> Anonymous: Redirect /login?error
    AccountLocked --> Anonymous: Redirect /login?locked

    Authenticated --> Authorized: hasRole() / hasAuthority()\nchecks PASS
    Authenticated --> AccessDenied: hasRole() / hasAuthority()\nchecks FAIL
    Authenticated --> SessionExpired: HTTP session timeout\nor JWT expired

    Authorized --> [*]: Request served\n200 OK
    AccessDenied --> [*]: 403 Forbidden
    SessionExpired --> Anonymous: Must re-authenticate

    Authenticated --> LoggedOut: POST /logout\nSession invalidated\nSecurity context cleared
    LoggedOut --> Anonymous: Redirect /login?logout

    note right of Authenticated
        SecurityContext stores Authentication
        ThreadLocal — one per thread
        Cleared after each request (stateless)
        or stored in session (stateful)
    end note
```

---

## 10. CSRF Protection

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        CSRF ATTACK EXPLAINED                                │
│                                                                             │
│  1. User logs into bank.com — browser stores session cookie                 │
│  2. User visits evil.com (attacker's site)                                  │
│  3. evil.com has hidden form: <form action="https://bank.com/transfer">    │
│  4. Form auto-submits (JS or img tag trick)                                 │
│  5. Browser sends request to bank.com WITH the session cookie               │
│  6. Bank's server sees valid session → processes transfer!                  │
│                                                                             │
│  WHY cookies are vulnerable: browsers auto-send cookies for every request  │
│  to the matching domain, even from other websites.                          │
│                                                                             │
│                    CSRF PROTECTION (Spring Security)                        │
│                                                                             │
│  1. Server generates unique CSRF token per session                          │
│  2. Token embedded in every HTML form: <input name="_csrf" value="..."/>   │
│  3. Or sent in cookie: XSRF-TOKEN (for JS frameworks)                      │
│  4. Client must include token in POST/PUT/DELETE requests                   │
│  5. Server validates token — evil.com can't forge it (cross-origin)        │
│                                                                             │
│  WHEN TO DISABLE CSRF:                                                      │
│  ✓ Stateless REST APIs (JWT in Authorization header, not cookie)           │
│  ✗ Web applications with form-based login (NEVER disable)                  │
│  ✗ APIs that accept cookies for authentication                              │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Password Encoding

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    PASSWORD ENCODING BEST PRACTICES                         │
│                                                                             │
│  NEVER:  Store plaintext, MD5, SHA-1, SHA-256 without salt                 │
│  ALWAYS: Use adaptive hashing: BCrypt, Argon2, SCrypt                      │
│                                                                             │
│  BCrypt (recommended, default in Spring Security):                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ Input: "password"                                                   │    │
│  │ BCrypt(strength=12, random_salt):                                   │    │
│  │ "$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"  │    │
│  │                                                                     │    │
│  │ Format: $2a$  12  $  SALT(22chars)  HASH(31chars)                  │    │
│  │          ↑    ↑      ↑               ↑                             │    │
│  │       version cost  random salt     actual hash                    │    │
│  │                                                                     │    │
│  │ Same input DIFFERENT output (random salt each time)                │    │
│  │ BCrypt("password") → "$2a$12$abc..." (different salt!)             │    │
│  │                                                                     │    │
│  │ Verification: passwordEncoder.matches("password", storedHash)      │    │
│  │   → extracts salt from stored hash → re-hashes → compares          │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  Work factor (strength) selection:                                          │
│  • Too low: fast to crack (GPU brute force)                                │
│  • Too high: slow login (user experience degrades)                         │
│  • Recommendation: choose strength where hashing takes ~100-300ms           │
│  • Benchmark: new BCryptPasswordEncoder(12); — adjust as hardware changes  │
│                                                                             │
│  Password Encoder Delegation (Spring 5+):                                  │
│  DelegatingPasswordEncoder supports multiple algorithms simultaneously:     │
│  {bcrypt}$2a$10$...   ← BCrypt encoded                                    │
│  {noop}password        ← Plaintext (dev only, never production!)           │
│  {pbkdf2}...           ← PBKDF2 encoded                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Quick Reference

### SecurityFilterChain — Common Patterns

```java
// Permit all (public)
.requestMatchers("/public/**").permitAll()

// Require specific role
.requestMatchers("/admin/**").hasRole("ADMIN")

// Require specific authority (exact string)
.requestMatchers("/write/**").hasAuthority("WRITE")

// Multiple roles (any one)
.requestMatchers("/ops/**").hasAnyRole("ADMIN", "MANAGER")

// Require authentication (any role)
.anyRequest().authenticated()
```

### Method Security — SpEL Cheat Sheet

```java
// Role check
@PreAuthorize("hasRole('ADMIN')")

// Multiple roles
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")

// Authority check (exact)
@PreAuthorize("hasAuthority('READ')")

// Use method parameter
@PreAuthorize("#username == authentication.name")

// Complex expression
@PreAuthorize("hasRole('ADMIN') or #doc.owner == authentication.name")

// Check return value
@PostAuthorize("returnObject.owner == authentication.name")

// Filter collection
@PostFilter("filterObject.owner == authentication.name")

// Call a Spring bean
@PreAuthorize("@myBean.customCheck(authentication, #id)")
```

### Session vs. Stateless

```java
// Stateful (form login, web apps)
.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

// Stateless (JWT, REST APIs)
.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```

---

## 13. Running Each Module

### Prerequisites
- Java 17+
- Maven 3.8+

### Module 1 — Basic Security (Form Login)
```bash
cd module1-basic-security
mvn spring-boot:run -Dspring-boot.run.profiles=inmemory
# Open: http://localhost:8081
# Login: user/password, admin/admin123, manager/manager123
```

```bash
# HTTP Basic profile
mvn spring-boot:run -Dspring-boot.run.profiles=httpbasic
# Test: curl -u api-user:api-pass http://localhost:8081/api/user
```

### Module 2 — JDBC Auth
```bash
cd module2-jdbc-auth
mvn spring-boot:run
# Swagger: http://localhost:8082/swagger-ui.html
# H2 Console: http://localhost:8082/h2-console (jdbc:h2:mem:securitydb)
# Test: curl -u dbuser:password http://localhost:8082/api/profile
# Test: curl -u dbadmin:admin123 http://localhost:8082/api/admin/users
```

### Module 3 — JWT Auth
```bash
cd module3-jwt-auth
mvn spring-boot:run
# Swagger: http://localhost:8083/swagger-ui.html

# Step 1: Login
curl -X POST http://localhost:8083/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"jwtuser","password":"password"}'

# Step 2: Use the accessToken
curl http://localhost:8083/api/profile \
  -H "Authorization: Bearer <accessToken>"
```

### Module 4 — OAuth2
```bash
cd module4-oauth2
# First: configure client-id and client-secret in application.properties
# (Register app at Google Console or GitHub Developer Settings)
mvn spring-boot:run
# Open: http://localhost:8084
# Click "Login with Google" or "Login with GitHub"
```

### Module 5 — Method Security
```bash
cd module5-method-security
mvn spring-boot:run
# Swagger: http://localhost:8085/swagger-ui.html
# Test admin:
curl -u admin:pass http://localhost:8085/api/documents
# Test user (403 - @PreAuthorize blocks it):
curl -u user:pass http://localhost:8085/api/documents
# Test user's own docs (@PostFilter):
curl -u user:pass http://localhost:8085/api/documents/my
```

### Run All Tests
```bash
# From parent directory
mvn test
```

### Build All Modules
```bash
# Skip OAuth2 module tests (needs real provider):
mvn clean package -pl !module4-oauth2
```

---

## Project Structure

```
spring-security-learning/
├── pom.xml                          ← Parent POM
├── README.md                        ← This file
│
├── module1-basic-security/          ← Form Login + HTTP Basic
│   ├── config/InMemorySecurityConfig.java
│   ├── config/HttpBasicSecurityConfig.java
│   └── controller/HomeController.java
│
├── module2-jdbc-auth/               ← Database auth + UserDetailsService
│   ├── entity/{AppUser,Role}.java
│   ├── repository/{User,Role}Repository.java
│   ├── service/CustomUserDetailsService.java
│   └── config/{SecurityConfig,DataInitializer}.java
│
├── module3-jwt-auth/                ← JWT stateless authentication
│   ├── util/JwtUtil.java
│   ├── filter/JwtAuthenticationFilter.java
│   ├── controller/AuthController.java
│   └── config/SecurityConfig.java
│
├── module4-oauth2/                  ← OAuth2 / OpenID Connect
│   ├── config/OAuth2SecurityConfig.java
│   └── service/CustomOAuth2UserService.java
│
└── module5-method-security/         ← @PreAuthorize, CORS, Exceptions
    ├── service/DocumentService.java
    ├── service/DocumentPermissionEvaluator.java
    ├── config/MethodSecurityConfig.java
    └── exception/SecurityExceptionHandler.java
```
