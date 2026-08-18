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
9. [Module 6 — JWT Signing Algorithms, Refresh Tokens, OAuth2 Grant Types](#9-module-6--jwt-signing-algorithms-refresh-tokens-oauth2-grant-types)
10. [Module 7 — Advanced Security: Brute Force, Role Hierarchy, Security Headers, Audit](#10-module-7--advanced-security)
11. [Security State Diagram](#11-security-state-diagram)
12. [CSRF Protection](#12-csrf-protection)
13. [Password Encoding](#13-password-encoding)
14. [Quick Reference](#14-quick-reference)
15. [Running Each Module](#15-running-each-module)

---

## 1. Architecture Overview (HLD)

Spring Security works as a **servlet filter chain** that wraps the entire Spring MVC application.

![Spring Security High-Level Architecture](https://www.plantuml.com/plantuml/png/RLDDRzGm4BtxLmpb0eSjiA9IsmFQpwX8hLGrombny3gpkrOTEumdBGkgn8_W5_9B63lPT44aKfJCU_FcpKmyYQo9szgf5xp36g5nsdeLxwrlDEaQJAYRuD5poNk7G6XO-wt38yfQc_ijXTPNy-02mSjYckx_YS0F1J3xbxyyBzuNYuG4gf3wwFZY_EtiGg95yDp7tat7P-D2FHrfQwBmc7Lxpbc-XAFOibWk6x9-2oMQbYpluVVFNt1bjxlHDJwWWocPdMLfgoLKgX5lUejmCdTM_9vauSypAH6Hu0tSXBKLpMdJV04TmMHMgZKazkLc8N2YEMiqs-1xfS55OHsBudmduyvISMCIOM5Zezdia4ga1uUSmIeAzknD1aB1EQJOoKhUtR9SmH7GsMDo0ZyT9myEFleDwSZKvjO7eMahFuBdtlQDzf95MKtN7UEJZ6A1hAsBoQCrcE4scnJyLiVuA9jSUXEgFhV13ZjKJqxnMzTSDBt7IhDUwoWc5_9MXfQC-4hjhzE8ks73QFGX3GikuMgrkeKx_DfYP9L22P9VuXBqSnFuwhMIM8B4eM0kw2grCDkdfzTrOYGeKQgrCChbzNA-WbRWGsg34g_pOgBG3yLYiX4va1mSMRknZNO3cAirCWomc-meaFsEbUfBfUK8GGu2eyeVfwUzukJl9TmEqcg2lfBJ-WS0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
skinparam componentStyle rectangle
title Spring Security — High-Level Architecture

package "Client" {
  [Browser / Mobile App] as client
}

package "Spring Boot Application" {
  [Security Filter Chain] as sfc
  [DispatcherServlet] as ds
  package "Controllers" {
    [REST Controllers] as ctrl
  }
  package "Security Infrastructure" {
    [AuthenticationManager] as am
    [UserDetailsService] as uds
    [PasswordEncoder] as pe
    [SecurityContext] as sc
  }
  database "DataSource" as db
}

client --> sfc : HTTP Request
sfc --> am : authenticate()
am --> uds : loadUserByUsername()
uds --> db : SELECT user
am --> pe : matches()
sfc --> sc : store principal
sfc --> ds : pass if authorized
ds --> ctrl : route
ctrl ..> sc : @AuthenticationPrincipal
@enduml
```

</details>

---

## 2. Spring Security Filter Chain (Core Internals)

![Spring Security Filter Chain](https://www.plantuml.com/plantuml/png/TLFBJXj14BpFLtJWaXmYEJoam05X6wy0SR22-O1Xjeqx7iyiFRqn94BY8_X2lYGzku2zAw6zhAgggwjQkwT9B4kzykQBB725K7bBmQGbXSgoNS6jTSixZdKenz57XjrYc9yjHSBx6eD3-6S0Xinn_QRS6-zF3WSANj4ShoZWA7A9t6Ud6e0SLJP8Lt3qSp0wwWdwQIQZuh0OcITZXCGZN5TCuGwkqTLCyWW5UK66yIAtCjN62NREPxCf_ChXa-o0JS1utrMykunZ47oGANAY9BbhQzjC9LVDksCt2JdO5KvjIcjjDAnbiJLGLxOtSBcMdkRtMhgIoOF3IYY66TkGlCslMtgKdcNBlHUuqFoS3M8hdoVgodD3Zjw_sJbXRupU0xwVD0NX631xW6iEsK1AvIfAbR5Tz_MRQH1bj42No83Y6hIBPq1nJTJ5Cw1uJgA4rVD4fhzOmklp2r3u4vTeMj67wz0vJEaC0s7vSQzsWMfocsCu6En34VcMoXBrWsXIRGnqYzOarvptSuiVS1CsYOmvnL3gB_GV)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
skinparam backgroundColor #FAFAFA
title Spring Security Filter Chain

participant "HTTP Request" as req
participant "SecurityContextPersistenceFilter" as scpf
participant "UsernamePasswordAuthFilter" as upaf
participant "JwtAuthFilter" as jwt
participant "ExceptionTranslationFilter" as etf
participant "FilterSecurityInterceptor" as fsi
participant "Controller" as ctrl

req -> scpf : enter chain
scpf -> upaf : doFilter()
upaf -> jwt : doFilter()
jwt -> etf : doFilter()
etf -> fsi : doFilter()
fsi -> ctrl : authorized — invoke

fsi --> etf : AccessDeniedException
etf --> req : 403 Forbidden

jwt --> etf : AuthenticationException
etf --> req : 401 Unauthorized
@enduml
```

</details>

### Key Insight: Filter Order Matters

Filters are evaluated **in order, top to bottom**. The first filter that handles the request (e.g., JWT filter) sets the `Authentication` in the `SecurityContext`. Later filters see the already-populated context.

---

## 3. Authentication Architecture (Class Diagram)

![Spring Security Authentication Class Diagram](https://www.plantuml.com/plantuml/png/dLHDJyCm3BtdLmHn6K9520c9JTE0Rkp4bpJu0LvgYbcQL4aAcX3_dMHRjwLRTvXwiv-Vd-sNtba7nbM5P2Vk4mlafGHIpCv8bM2Wu4A2jIc8MMvqfRAXbjhmquTqV3rETs3QP6XMaAlkpMNQtO9CcoJZ-_0nviX9v9FIaChv14LboCtvVUK5AKS276d5Xw417n7adeinKWxD1mXiuduPv-SvkcSei7FMunCNQ5V1eS4iO47Qa7kPVg5mgrpWqRupuIBdDKgVz9GXJtQh3MO1CDLQ8YZsroxc2HJaQ9QQO8kW4-CyMnmuHFfgz3TbHx5wlAtAKXjdEujzzcy7yIIBC_AwHQsVYb9wRoXd3moObAigs-EFP5r_l-p1CRjOoXg1Rbb5gy1eMKbbqOpG0KaxGVDD0dlyVIUscCNt-_5kVb12-_8UVuq36r6XNdclrO2u_vkUeMgNLo-EbA0Iv9OZ4x6nwZeSkM9N-D8HKaCMSkcybjPPle6pQDXMilKBMfStNr4zwawY_GdvParJwIGPj5oBjLyw5EqvsU62vl7shExY8k9bx0vLvd-B_m00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
skinparam classBackgroundColor #EBF5FB
skinparam classBorderColor #2980B9
title Spring Security Authentication Class Diagram

interface Authentication {
  +getName(): String
  +getCredentials(): Object
  +getAuthorities(): Collection
  +isAuthenticated(): boolean
}

interface AuthenticationManager {
  +authenticate(Authentication): Authentication
}

interface AuthenticationProvider {
  +authenticate(Authentication): Authentication
  +supports(Class<?>): boolean
}

class ProviderManager implements AuthenticationManager {
  -providers: List<AuthenticationProvider>
  +authenticate(Authentication): Authentication
}

class DaoAuthenticationProvider implements AuthenticationProvider {
  -userDetailsService: UserDetailsService
  -passwordEncoder: PasswordEncoder
}

class UsernamePasswordAuthenticationToken implements Authentication {
  -principal: Object
  -credentials: Object
}

interface UserDetailsService {
  +loadUserByUsername(String): UserDetails
}

interface UserDetails {
  +getUsername(): String
  +getPassword(): String
  +getAuthorities(): Collection
}

ProviderManager o--> AuthenticationProvider
DaoAuthenticationProvider --> UserDetailsService
DaoAuthenticationProvider --> PasswordEncoder
UserDetailsService ..> UserDetails
@enduml
```

</details>

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

![Module 1 Form Login Sequence](https://www.plantuml.com/plantuml/png/XPJBRjf058RtynIdBWjR0aA88ZLPLC5SsbJGM3NikfdO9p32dd5dnaqHGkf3z0dx93s-0IQBoWjVpZV__ES_8pyOoxNDquIzinjC4RA42ydCLiYCQvx2Cu-sQwro6OzLeZIydusAwumm-2D76I7i6S18Q_LQayFnpVHsG1_duWNdGgAlT8pwiXgG0H69Z4lR1ku-3Fox2-3IpTIVtSvyTc3C2fiWB5ISq-qQ_lx-0pEbKvYhjP0GrYOPuv6bXJxPDAXPTj86PnMCPj-bkwA2v2a6t9XNSZJAxMOc4elQSu0Ro3F-qbuOQFLJaFC5btoDkgIojCrCk2g46hHaOfwreKUvm5JftMeILbl5fWtuOxtBx5H6gj78i4s46ELQsDrOIOk_RCcOgCryNYu3YiGOeMG5q3DZTIZG-rZs2FSGF8LBk4hA2FTvdKiNiZgP0oivuhEKQ4xzeQHjk4Lt9SlNUAcsA3r6067Ky7-uWYZsZms1YU9nCGr_ryp4TGeNZiSAe7TKBCeJj5ma1lPLHcvXqkk2LWcQGwER8T4fjz46ZUiqVJXTS3f3thaUTlhzFgaJTXAtEiTgVTFewAo1ohXxvg1RDgXe209DrVafqRTBZncQYEe6xHb2yt5j5SoHeb4L79rYX8jXrn1HpIZluMOmX6yO2usHXQkOcyspuZfkJRlM_3HTdX7WVWcdOVZuzFLn0f5IMu4UAybUOxQOpniFL6ax60u6BLcDaWulnXvZ3_H8Fvz_)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 1 — Form Login Sequence

actor Browser
participant "UPAF\n(UsernamePasswordAuthFilter)" as upaf
participant "ProviderManager" as pm
participant "DaoAuthProvider" as dap
participant "InMemoryUDS" as uds
participant "BCryptEncoder" as pe
participant "SecurityContext" as sc
participant "HTTP Session" as sess

Browser -> upaf : POST /login {username, password}
upaf -> pm : authenticate(UnauthedToken)
pm -> dap : authenticate(UnauthedToken)
dap -> uds : loadUserByUsername("user")
uds --> dap : UserDetails {BCrypt(pass), roles}
dap -> pe : matches("password", "$2a$12$...")
pe --> dap : true
dap --> pm : AuthenticatedToken(UserDetails, authorities)
pm --> upaf : AuthenticatedToken
upaf -> sc : setAuthentication(token)
upaf -> sess : store SecurityContext
upaf --> Browser : 302 Redirect /dashboard

Browser -> sess : GET /dashboard (JSESSIONID cookie)
sess --> sc : load SecurityContext
sc --> Browser : 200 /dashboard (rendered)
@enduml
```

</details>

### Sequence Diagram — HTTP Basic

![Module 1 HTTP Basic Authentication](https://www.plantuml.com/plantuml/png/bLHRRzCm57xthpY4bqRQjB8BOdr0QzeK46qtzO8s0K9UVDQP9dPcEumE8V743q3ymlqIZjDaMueqX28bolakv-Rao3fkN96bx8cxn0mXJxbKp2wbohdX6PppPBamkb2YfrDjuEcWwwy738jN1Qe4uHi3w1gZholcRcylFcXJS2WlS2WLHje8D9le2HKW4vbpvPg4mnVjw723i5bD70qE1X7xpfYJBaKOQL7GundS_lWDhsUp4uYubGbq2sfFaGrtKYjeJHrtcAAr8MCySMJLIoKHM7wV389IwwK3cJeq0N1B0xbeaZm-ueelAWBFclYyFotZXR1DO8f9OQHRzRHo-DML99imjgu4jb_wND21L_4CTdWkTmgBveFo-RIHDsKddQe_SJfEay_vzTdf-8PvsPsQS7o-3m8JBH1kV_w2mFjqScvjK5DfZHtWzpF2rboLhsAcbwXQfIJO2afH63BYauew8bcgkPWJ7AtyNV4CAth8F66xjlTe7nsNgItrTnK-s4sLhoxB9WHRTCtjjPpdX6iIiQfvTM2ttORZjumfxH3q5woNkhKs6cloijRltv-EP2tB2kiehWHS8gVJ1mJ7x-B96HX_iArxP25SP5BznqR-7dC8x_c2lZWgiJwH7_yr7MXDZeVnf_aqdb2nwIfyV5oCmeqnxRVtOA3DkHJ2cob4MbDfsUsFtepfYpYYST0_uGy0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 1 — HTTP Basic Authentication (Stateless)

actor Client
participant "BasicAuthFilter" as baf
participant "AuthManager" as am
participant "UDS" as uds
participant "SecurityContext" as sc

Client -> baf : GET /api/user\nAuthorization: Basic dXNlcjpwYXNz
baf -> baf : Base64 decode → "user:pass"
baf -> am : authenticate(UnauthedToken("user","pass"))
am -> uds : loadUserByUsername("user")
uds --> am : UserDetails
am --> baf : AuthenticatedToken
baf -> sc : setAuthentication(token)
baf --> Client : 200 OK

note over Client, sc : No session — client must send header on EVERY request

Client -> baf : GET /api/admin\nAuthorization: Basic dXNlcjpwYXNz
baf -> am : authenticate() [again, stateless]
am --> baf : AuthenticatedToken (ROLE_USER only)
baf -> sc : setAuthentication
sc --> Client : 403 Forbidden (needs ROLE_ADMIN)
@enduml
```

</details>

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

### LLD — UserDetailsService Class Diagram

![Module 2 Custom UserDetailsService LLD](https://www.plantuml.com/plantuml/png/TLJjQjim5Fslfz2oFycobAqmQ4qmZVCnDjnsnElleTYtYOWi2KdU6iPW3x4dt9DKLx5JDt4mnDRzEFVSSwzoOnqphYe5UUCsK0BLWd59x9PBpGmhQIwOjGdBjskZAbbCbL26lfqdYq-Bv2HCcG9C7N9vVVKXkMw5h8v15XDy277S2Q2tggZywvB-__kFJYlhL4aVB9WPECQ5pS3yv3dGD9qH4ghLGHqnlmcbeyhRbw2LvKwPNHImNiu-OYWKAz2QxF1NiXBwcJDShWTHkpA2bKmlbG3xNKqgjr66Emwsdu4Repds2VZzsJ3fe6X2TZ7vqt2TQ8sGUsgyY6YgvBgXYQKzGgYDDkqpVdaj6nkbut4oDJljw8RPJHnZa44--xg10zf0ifK0dxTItiGasbYUUytTdPBp9ytDMM-gyksHC_VH81rdmdQb7vh3-gUTjRl23fRtwVp7GpPVlgVXSpAx_N8N1usubyqyCZ-wrrFoMLyrUpd7SIWpVEIow9hQlNPSIIR6jTmeoX2Uk7MsAxpLo6i6zUHz-Km7-XdaLPXeJM0DxW0tQ8qE7T_gwPqusglZVVuM2CYHCFgvdU-7rnzqA9pnKWiutg-zvgmvTeeTbgLTVTVYvV7FNgBHA3w-CqV3kRY83tiTKRnDbZJdtiTUGEYzw-tN8yBLFLyDiThAHzI0guoqf6r5n6uf2Ba1MVZ_iMS0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
skinparam classBackgroundColor #EBF5FB
skinparam classBorderColor #2980B9
title Module 2 — Custom UserDetailsService LLD

class CustomUserDetailsService {
  -userRepository: UserRepository
  +loadUserByUsername(String): UserDetails
  -mapRolesToAuthorities(Set<Role>): Set<GrantedAuthority>
}

class AppUser {
  -id: Long
  -username: String
  -password: String  <<BCrypt hash>>
  -roles: Set<Role>
  -enabled: boolean
}

class Role {
  -id: Long
  -name: String  <<ROLE_USER, ROLE_ADMIN>>
}

interface UserRepository <<JpaRepository>> {
  +findByUsername(String): Optional<AppUser>
  +existsByUsername(String): boolean
}

interface UserDetails <<Spring Security>> {
  +getUsername(): String
  +getPassword(): String
  +getAuthorities(): Collection
  +isEnabled(): boolean
}

class SimpleGrantedAuthority {
  -authority: String  <<ROLE_USER>>
  +getAuthority(): String
}

CustomUserDetailsService --> UserRepository
UserRepository ..> AppUser : loads
AppUser "1" --> "*" Role : has
CustomUserDetailsService ..> UserDetails : returns
UserDetails --> SimpleGrantedAuthority
@enduml
```

</details>

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

![Module 2 JDBC Authentication Sequence](https://www.plantuml.com/plantuml/png/XPJjRjem58R_vohEilveDThIe4fhjLKb8RHZj5HyxCS-D1qIKomIsxETLGnLsaNi2dSbEmwXD6pIX0I4y_ZrUzvZSsaiQblacVV2pbdEG6N8XMSMN2ZKcCCKayMzbeL88vb93I-xRVTwHXZshM0YOR3o0DfQouUA3A9MVDga7_jynlfSi53gbEdTwXqPu0bNA6mTE7lT3CzsW5qtSTWzxORUe-TPRZC6Dp8jw2E0tpz_GQyJHj0kg3510cYv532gt7eU9fOKeenJrLFRFS0FqV34hUlop3Bj0nhAOLQ7xhJypidj3Ggyho2LrvaEIYUpGKicHLM7ei9OcKywexAS5AcfroU6wI5Jqd3okomXJOzUYXQdQ1Zurm5qmhNuTAUJI2-LZKKYDzihwdpTCnnUkAxW7AxYCHoZuiTAondFs6VXN4lDVvIPdKCP27oywfqamOVbG8Jpf7NRchPw2yyfa93AIGUtKRFzYIWVqx5SC77W4K0ODVyVpX44kXY8p2IchlzmwTu5vcpVJwS5VVSFl98XrgL1x8oBz9zSMNURJuaQnVqu6eChmIlGCcC6UeDtjnvL3xTYRQMSqge4tduQ3lhnryae7dvvhEIs7WVAXOJPcshDnPEn2iXH3PtCM5QnMixC_ZFDJIjF0JcP3hF8CxDQZ_0QpRm1DHzLKegLMzXaJgA-GcCUw1Rv3V3t0jmx2VQEZeue1CAs-bONRBr-CxfdjwGQHTsW6z_JUVaRNXy30ggZTGv1imc3zx0ggdaqogbNpTDrlMGYfR-TFm00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 2 — JDBC Authentication Sequence

actor Client
participant "BasicAuthFilter" as baf
participant "ProviderManager" as pm
participant "DaoAuthProvider" as dap
participant "CustomUDS" as cuds
participant "UserRepository" as repo
database "H2 DB" as db
participant "BCryptEncoder" as pe

Client -> baf : GET /api/profile\nAuthorization: Basic ZGJ1c2VyOnBhc3N3b3Jk
baf -> pm : authenticate(UnauthedToken)
pm -> dap : authenticate(UnauthedToken)
dap -> cuds : loadUserByUsername("dbuser")
cuds -> repo : findByUsername("dbuser")
repo -> db : SELECT user + roles JOIN
db --> repo : AppUser{roles=[ROLE_USER]}
repo --> cuds : Optional<AppUser>
cuds -> cuds : mapRolesToAuthorities([ROLE_USER])
cuds --> dap : UserDetails{BCryptHash, [ROLE_USER]}
dap -> pe : matches("password", "$2a$12$...")
pe --> dap : true
dap --> pm : AuthenticatedToken([ROLE_USER])
pm --> baf : AuthenticatedToken
baf --> Client : 200 OK {username, authorities}
@enduml
```

</details>

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

![Module 3 JWT Login and Protected API Access](https://www.plantuml.com/plantuml/png/TLJ1Rjf04BtxAwRkXKW9KA983OSgXa9Q2WeIe5vwsQm7s61stTrnI1eXzIFwXVsIpjeEs4GL4h1-RzxEUpFoZIDXATicmJjQunOXJOJIWTiedGehjd0lv6PbJQRZlacCXVV3o7yg38S_CzGIuIK0YAmrkvBPwLyEhjhySAoME5OQUyR6Q4_HAJUWf4g5fZhX-cExTtr2EErcq1jU3Nl1FWX8KO8mCN76FvVmz_SV67sVmzYib0QXOvXQGoW9OuYcNo6I4fqB0Y69TVg9Gar1Uhm9mkdTR0ujaT6wbNYH48I3_5-T5p5Z8hHOeSqfObl7HpjQa4fox657Rq1VFrG9bUKFObcdp51cLj5pdvvoWfDr_7RWsqnLAxLcgH8icaXL4FYaKfWHfl2XMqbYXUIpuMWBtt3ngJ06NNZ975ejjdWEgN1knnFPCx60cSS3xu8FXUkK58IDXSwFyTniK9ynboaN5SMeGYv8LJrEX3ahr6WPp-66R-4pab29ytgUKXKCyNcqlh-LgjbiXaSjPfHss8N8nvlBdOF5fKMtpa_x07LSYwRJBPS1qiE6CDraLc8j8fuCIv_6_KDxWyQgNuAKqLteeR1eeTAazy2r1xVuH9RtRb4ctQ3Nv5wT5ZU5VFHHXD1uHAkMYXlxCedwPwTwZo9HyI4zAap_9yH2cco6HnKd-P53gaoAdJJU3gvoCoV0HT8mhZE4PRx08DV-xG4vMXj8fzs6ks_LxH95QgJGbJEvuMz-4_q3)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 3 — JWT Login and Protected API Access

actor Client
participant "POST /auth/login" as login
participant "AuthManager" as am
participant "JwtUtil" as jwt
participant "JwtAuthFilter" as jaf
participant "SecurityCtx" as sc
participant "GET /api/profile" as api

group Step 1: Login and get JWT
  Client -> login : {username, password}
  login -> am : authenticate(UnauthedToken)
  am --> login : AuthenticatedToken
  login -> jwt : generateToken(userDetails)
  jwt --> login : "eyJhbGci..."
  login --> Client : {accessToken, refreshToken}
end

group Step 2: Access protected resource
  Client -> jaf : GET /api/profile\nAuthorization: Bearer eyJhbGci...
  jaf -> jwt : extractUsername(token)
  jwt --> jaf : "jwtuser" (verified HMAC)
  jaf -> jwt : validateToken(token, userDetails)
  jwt --> jaf : true
  jaf -> sc : setAuthentication(AuthenticatedToken)
  jaf -> api : continue filter chain
  api --> Client : 200 OK {username, authorities}
end
@enduml
```

</details>

### Sequence Diagram — Invalid / Expired JWT

![Module 3 Invalid JWT Rejection](https://www.plantuml.com/plantuml/png/PLDDRnCn4BtxLmpB9Jaq2PHAD0VK96mGLO6g1BZqOhoJnitks7Z7RT8AYHC_0F4B-qiO9od9fjg3Lvutxxtvy4dDEd2iIlMCPrWX-59RKlNSajT1L_1Tc_bLS96AaIjTWEVZGVfs43N-Y4W6uLu1349mjnlaoz5XVjIJopCxnJDBE7IXmB0VFHS3rbYlYPk0uzUzuV4UODzDFXmVZOVgfr9ikKJuu8eeno4y_FeBx-b6bxQ0BkGBRmCMSFfj0XTuZOQj8wMqOI4PbHQ9bT_AG7PwouF8ix4j6KC6kePhFMr2Kjm5UwSJrmvGo_tTKsXE79RdpXAlKEYLMWl3mPj43drubq-Wgxtj-k2cjiHBQcZqOOWwO01SLzDXDqVgp32WIWJ_UMmzIP5DqQqsFFp-0nmYAdACu6w4Outyclgp8eUf5iNYajuw-FXf8bDbIEfYq9ermX9yHXE3vUN84UE27sLN9GjTkhOK4SnCjWXQvFOpm3iVIyrOjDKwQoVz2hafkR4-84VBoiMw6LqL-PH5q_8YhMJDhNP7RpDI9wIZZrmGQsb3gheMksZcMoRqGcDSLQMrRZL5yuL1dtxQIc07WjvCiG-lUY_W2-dDo58lxpEKzn2oVhRNoY06qsmoMTmJf48Uu3y0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 3 — Invalid / Expired JWT Rejection

actor Client
participant "JwtAuthFilter" as jaf
participant "AuthorizationFilter" as authz
participant "AuthEntryPoint" as ep

Client -> jaf : GET /api/profile\nAuthorization: Bearer expired.token.here
jaf -> jaf : isTokenExpired() → true
note over jaf : Validation failed\nDo NOT set Authentication in SecurityContext
jaf -> authz : Continue chain (no SecurityContext populated)
authz -> authz : getAuthentication() → AnonymousAuthenticationToken
authz -> authz : anyRequest().authenticated()\nAnonymous user fails check
authz -> ep : commence(AuthenticationException)
ep --> Client : 401 Unauthorized\n{"error":"Authentication required"}
@enduml
```

</details>

### Token Lifecycle State Diagram

![Module 3 JWT Token Lifecycle State Diagram](https://www.plantuml.com/plantuml/png/TPFDRjGm4CVlVef1NBgegwqeHRI7gfkoAnL1gUWA3i31SMOJiuuTx4cs4KBgG_G9UHB6-MXtaL0ESMP-yvyFJou2IKzrQSGpAh14g8pKLeIDjfNqieHKgatkNMspIsUSX-VBUNns25OWX5y28FcNNIJBasKIFSvdw0VhozCtHyafM-VUk-rel3nUd1o9tqAG9eFmmMKrluxXp_q3lFkoWfNRe8NtUesgLUovxTA-rJBd8eJu-k8xJAVdSEteAeGQCo4UZvrZhaWt26Tmy_5s1JDPKp4pBjVscprefD4PA8yPMjBIX8aOyBt8pntcyMUDWM2hgG2ALR62TGHuLscME8IWSokfzWYTy9xOeeTOZJIF-pn6WUAXbxlK9snOE59Segi9PdqcI0tFsEX0OXJwNsyUrnv3yTZTyDthJFR2u-pEzW7W8RYn8p6MymGhQMFBAK8Ts27pk3Kx3LpPFYktASiAOwOPRBsp-TDqn0Zjrl035J6SjX3GD-Y5u3m8NkS5WLiFhVBozFlG2SWOuImWy-ruFunSkq5a6dI6V0v1CnR8UPb7ZHlP6YSpQ7JGAU_KGI83ldurEOJkFgtoRSNQ0cqMBIZ41H_vR_aB)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 3 — JWT Token Lifecycle State Diagram

[*] --> NotIssued

NotIssued --> Active : POST /auth/login\n(valid credentials)
Active --> Active : Valid request with token\n(not expired, signature valid)
Active --> Expired : time > exp claim
Active --> Revoked : logout / token blacklist
Expired --> Active : POST /auth/refresh\n(valid refresh token)
Expired --> [*] : refresh token also expired
Revoked --> [*] : cannot be used again
Active --> Invalid : tampered / wrong signature
Invalid --> [*] : rejected by server

note right of Active
  Token validated on every request
  No server-side session storage
  Payload visible (Base64), not encrypted
end note
@enduml
```

</details>

---

## 7. Module 4 — OAuth2 / OpenID Connect

**Location:** `module4-oauth2/` | **Port:** `8084`

### Concepts Covered
- OAuth2 Authorization Code Flow
- OpenID Connect (OIDC) identity layer
- `CustomOAuth2UserService` for user attribute mapping
- Multiple provider configuration (Google, GitHub)
- OAuth2 access token usage for API calls

### OAuth2 Authorization Code + PKCE Flow

![OAuth2 Authorization Code + PKCE Flow](https://www.plantuml.com/plantuml/png/NLDjQnf14Fw-lsAQGcb9OiHYQQGcEQ-QG0Mb9jy4sUwDTuldxdPsZQJYV-_iQTGJuUHcdzTPxi47IM6rBCM7KE0ImPLI6-4NsZX9SWb_f5haP5ScIsrf2JuEalWxGNZykqAZ43O2826owpsobNxjjviy7Eev3hN1dgKCwVnqp06qqawQK0VSVc_sRiy0vsdwlK5xq1DR8O8E9S8eMOMY1V5fIV-JGLi3gSqGBc7yA-t3eBHh8QGAp7xnIC8TrU4YBJNoV-BS1KWFqhdwULrtWlIAj4FwEl0tUhiYNie9XhmGqHAkxw8oT42LMYrWQ7DUUPmS3d8qI38WA8u-Om4zrqXJSxaRg4AM9PeSuVFaARbkjRzzEV0zqn_xpt0ZzrbnQku9lRF6uooyEUn6ZQdvL9VgDXeDmMpMg49sm1Ts3MKC1z6NwTpCoHoFBQ8P6vDznJrtbvymquGgm5g70kwZKpTvUNwQfQEV_LhKyMZ2MODTe9cQJGHUrKjltuKZkXg-xMxoaBm27AmtKYdqVbP9Nd6IEPSlTg_RTsiwRidf6zfVrjJKxhS3FPJ4JNzKv3j1fpwjPfFNmjK3zyGCCXca40zeClwQ_WC0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title OAuth2 Authorization Code + PKCE Flow

actor User
participant "Client App" as app
participant "Authorization Server" as as
participant "Resource Server" as rs

User -> app : click Login
app -> app : generate code_verifier\n+ code_challenge (SHA-256)
app -> as : GET /authorize\n?response_type=code\n&code_challenge=...
as -> User : show login + consent page
User -> as : approve
as -> app : redirect with ?code=AUTH_CODE
app -> as : POST /token\n{code, code_verifier}
as -> as : verify PKCE challenge
as --> app : {access_token, refresh_token}
app -> rs : GET /api/resource\nAuthorization: Bearer <token>
rs --> app : 200 + protected data
@enduml
```

</details>

### OAuth2 Key Concepts

```
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

![Module 4 OAuth2 Class Diagram](https://www.plantuml.com/plantuml/png/TPJHRjem58Rl_HIUTiFK8bNL9gseGWKwjcdga61z06CVWejZU_P99JPDsaFq2VSaEqu8IKbGBb3-y_i_NqvEk8ie0XQvOMzm2pbmRuIsBEwqzIA8d4iZOfmAkSk2AwoQEUC2V_jfElymdtPiBYW81ylrpSUhwKtBiZuDcK_InHXgDC0Vd2hevpt_z_U5BoO5Rg_vBANoUoqo2c2iR7AehK0MGUD-vkn6P_mtutpeoifZXB22yAmbZFYiYEZonMc1t1Vna33N1ebwIyyz-8Bew-Ht8xxgMjYVckDCT8MYm40ca0ZkOICAWxq8nWcLf45JNSBF0Y9IyqPBWRdmwTuHZeOuyC4zQnhs9HU88PQiUFiv28kWQkD-d6WrIM4ZYAn9B24lCi09dTRh0YcICXw4lrsHOBFBnVe998vhMwir-UW56gfgPtjQLYU-YnoIjOfhfjOP1zUvDxHv5kCfu50SwKgs95dAFK9_W_snGx8tbEKyMk_AQ6gmX4n732A1Lmr2I_cgsbcoFD6dqL84mBOUGEb0ytWCkYr7wNo7f7h4mxX-WQh8AXhPeHpra2UdfnvIUs7Ic5-DG4g8yOVRWQqtQD985UmcGDo-iYnRMa8zjzh3uVZiFlCHhvS-ijvlD9q-zpsU6Kjvf3i1TWTMqP_MVm00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
skinparam classBackgroundColor #EBF5FB
skinparam classBorderColor #2980B9
title Module 4 — OAuth2 Class Diagram

class OAuth2SecurityConfig {
  -oAuth2UserService: CustomOAuth2UserService
  +securityFilterChain(HttpSecurity): SecurityFilterChain
}

class CustomOAuth2UserService {
  -delegate: DefaultOAuth2UserService
  +loadUser(OAuth2UserRequest): OAuth2User
  -mapAuthorities(provider, attrs): Set<GrantedAuthority>
}

interface OAuth2User {
  +getAttributes(): Map<String,Object>
  +getAuthorities(): Collection<GrantedAuthority>
  +getName(): String
}

class DefaultOAuth2User implements OAuth2User {
  -attributes: Map
  -nameAttributeKey: String
  -authorities: Set
}

class ClientRegistration {
  -registrationId: String
  -clientId: String
  -clientSecret: String
  -redirectUri: String
  -scopes: Set
}

class OAuth2AuthorizedClient {
  -clientRegistration: ClientRegistration
  -principalName: String
  -accessToken: OAuth2AccessToken
  -refreshToken: OAuth2RefreshToken
}

CustomOAuth2UserService --> DefaultOAuth2UserService : delegates
OAuth2SecurityConfig --> CustomOAuth2UserService
OAuth2AuthorizedClient --> ClientRegistration
@enduml
```

</details>

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

![Module 5 @PreAuthorize AOP Interception](https://www.plantuml.com/plantuml/png/VPJ1Rjf048Rl-nHJUWYMcWerHMggAiA0KQaWe72jL6tM4rYntdLtrovf5AcdFa3L9-oJT6nZWqaKMSB2yyq__yoiFN2UMvybYhto6qmGKiMbPcuhTSejJ-2MY-tQcap78wECXTUJiBYE28VVCzG2uO41XDQQ7tlotUWYwlVeuKpUuKng71eRepsDBic053BbshU1om-zuUK9SEec6axwao5xPCnBhn3c9ixereT_l_x2O6anpFp6MFaJ8LmiOMdDxXwcsgCLc7ffD6FfGHuw8wEzDKgXxG1t8BnLRQ1H-QgxOoEo1BLVeSsbmA1CIOjWEsUEv25UeSYizFTDTLFLI9niuwiqca6arpIn4d0fdfYefGgtkFCL9ThCYJcoQv4hk4MkAwCk5umL3SBvLUKQFaBSpdgxHXygLMkvRi2qyGWcHzlaL4ELTLkkd7rJ32W11AUHnd2FdbLPL9BwfcIfSxF5RZMYAVqHl5XBm8emKKuGLBYWFP83MON91mNE6vLs51veXUWU6mqQ846OSvLnZztEXhiR8hfduNW-lJuBEcz0LACC6EFA0m5mivX5tqg0pc0fSQZdRORqjDRF2vFKc42Ckq7PVz5nDOIaRAtGo8yjpwJpd-h1NjLYHwju0kmdHqYvjIS4AeUGIEUaNh_e_euJ-Kn5lw6N5q8XqBanQebnjAjVasVAlumVpiaU7pJHprp7gWXmBpP8v-Nt7tZVku0lgyKrGnqpDg1V-YZz1m00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 5 — @PreAuthorize AOP Proxy Interception

participant "Controller" as ctrl
participant "AOP Proxy\n(DocumentService)" as proxy
participant "MethodSecurityInterceptor" as msi
participant "SpEL Engine" as spel
participant "SecurityContext" as sc
participant "DocumentService\n(real bean)" as svc

ctrl -> proxy : documentService.getAllDocuments()
note over proxy : Proxy intercepts — real bean not called yet
proxy -> msi : invoke(MethodInvocation)
msi -> sc : getAuthentication()
sc --> msi : Authentication {roles}
msi -> spel : evaluate("hasRole('ADMIN')", context)

alt has ROLE_ADMIN
  spel --> msi : true
  msi -> svc : proceed() — call real method
  svc --> msi : List<Document>
  msi --> proxy : List<Document>
  proxy --> ctrl : List<Document>
else missing ROLE_ADMIN
  spel --> msi : false
  msi --> proxy : throw AccessDeniedException
  proxy --> ctrl : throw AccessDeniedException
  note over ctrl : @ExceptionHandler catches → 403 JSON
end
@enduml
```

</details>

### Method Security Annotations Comparison

| Annotation | When Checked | Supports SpEL | Use Case |
|---|---|---|---|
| `@PreAuthorize` | Before call | Yes (full) | Primary recommendation |
| `@PostAuthorize` | After call | Yes (returnObj) | Check return value |
| `@PreFilter` | Before call | Yes (filterObj) | Filter input collection |
| `@PostFilter` | After call | Yes (filterObj) | Filter output list |
| `@Secured` | Before call | No | Simple role checks |
| `@RolesAllowed` | Before call | No | JSR-250 standard |

### CORS Flow Diagram

![Module 5 CORS Flow](https://www.plantuml.com/plantuml/png/dLJRRjD047tVhnZA2uWwCOs2g1-WjfL0HOEj9BprPLbFxAMRNRExRX08YO_W2_aIniw5D6svoPOjpPoPENDcTi-SvzOtIyKU-0gN2BNYKZDt9NNDBL_2UowkIciQNQH66GiFnt7xx24SVcnG2uGl322srgmso9DqC1g6PBoG2xoG6XDZ2xI7tfm8I25hhlrDmEdpC3az01oo6INZuJXXNndpqYk4YIaQ-WtXnxVla6RJ6OoLMJ76XITuGkGSMbR_oWX7gR5kB9L7UmJSWLZST4z7ipd4-NddvBLaJ1kFOAvnb--ujKC4ANS8JxlICxciYOUmnhd0M5bA3Qz6SxQ9WE055Q8Gia6Veli5z_nIPnqoWihxEkhtbH5SLSRvQ1268QE8RTmc9RrSKODOh2FTomreJMXXx8hR0cmx8kTPQmssAKx24B8ty0JQqbqOURRyjkvB7Gk1r4DgjBT61N5RBlWzppyeTD8fb5jSA5bMlcK9-RivCH6DysO95N9QWrjQPVdyF7ix-skzRd6VhcK89kWhKqHjqNinhpiEBeAu8R2LdxcNHk-Fu9ehIIpeoEmwuIKT7kT16BsGvNzgsklrxa6iURjkQuxpR4QVEpgOy4z1N684WsVjB0vLR9N-1mNtkuyWGMufruUL9vPthjgZpMPkrIaUxxRkK0SQU7T2r-DsZ9sXBkWg-Wa0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 5 — CORS Flow

actor Browser
participant "CorsFilter" as cf
participant "REST API" as api

note over Browser, api : Case 1 — Simple cross-origin GET
Browser -> cf : GET /api/data\nOrigin: http://localhost:3000
cf -> cf : origin in allowedOrigins?
cf -> api : forward request
api --> cf : 200 OK + data
cf --> Browser : 200 OK\nAccess-Control-Allow-Origin: http://localhost:3000

note over Browser, api : Case 2 — Preflight for PUT + custom header
Browser -> cf : OPTIONS /api/data\nOrigin: http://localhost:3000\nAccess-Control-Request-Method: PUT\nAccess-Control-Request-Headers: Authorization
cf -> cf : validate preflight against config
cf --> Browser : 200 OK\nAccess-Control-Allow-Methods: GET,POST,PUT\nAccess-Control-Max-Age: 3600

Browser -> cf : PUT /api/data\nOrigin: http://localhost:3000\nAuthorization: Bearer jwt...
cf -> api : forward (origin validated)
api --> Browser : 200 OK + CORS headers
@enduml
```

</details>

### Security Exception Flow

![Module 5 Security Exception Handling Flow](https://www.plantuml.com/plantuml/png/ZPJDRXCn4CVlVef1NDeJswGHf3cG3tP5GQLHKcwvkFOqjUgC5zjBco8aJZm0uWdx98ppiKctLA2LrlRO_xzdVlPkFqJfOxMmuaMynWL2QQKX4MuCbTBB1LnATJFthY8zSjPvU5aCqhEtGgfelfguX6y2ODXSdW-BJZ5CCyvhz9jeg_ic6tOvEl3UtMw3etRUoSJtFMzjvCAH_hjraHVT_7NJkcXtHqSjTX7HH8jmvdJ5JGSUVlo6AQhAfrppEuLbD8xWlIHj3SsXiEvMY1KFSN9AoYrIT89VAWon9ymL70mgXaJHA1bHlps4D883SeUSn4bjUU4b1IjJjp0sefyH2zGr1jWpuDbQqMDzyf_aqmiOZ4zhwoM6vCtk3IL5lnmxGt56nzaHV2R9yywRUzJmONh-gRTIXUXAxg0Dk4sJhIQeZKSL8JfuPTtSq8pQMGkAnFQnaBIv4clv9fKjXlLU3GR_Iq4f3E4Taa7zYC6_A2GEUzhLqINZuwpDsVjBepMltzLV5z9aqAIG34evnwUo5O6jV7SScsi1fNSAKOVaCd9yAivoHhjQ-cEFDIxU8WGCJw0roggHpEZXvo_er-DDlP2YdF4pDUxJEaFUMWFUyRsFJ3vz0wqiW_EFprUwFlFLM_IvvP_37m00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Module 5 — Security Exception Handling Flow

start
:Incoming Request;
if (Authenticated?) then (no)
  :ExceptionTranslationFilter\ncatches AuthenticationException;
  if (REST API?) then (yes)
    :AuthenticationEntryPoint\n401 Unauthorized JSON;
    stop
  else (no)
    :Redirect to /login\n302 Found;
    stop
  endif
else (yes)
  if (Authorized?) then (no)
    :ExceptionTranslationFilter\ncatches AccessDeniedException;
    if (REST API?) then (yes)
      :AccessDeniedHandler\n403 Forbidden JSON;
      stop
    else (no)
      :Redirect to /403 page;
      stop
    endif
  else (yes)
    :Request proceeds to Controller;
    if (@PreAuthorize passes?) then (no)
      :AccessDeniedException\n→ @ExceptionHandler → 403;
      stop
    else (yes)
      :Method executes — 200 OK;
      stop
    endif
  endif
endif
@enduml
```

</details>

---

## 9. Module 6 — JWT Signing Algorithms, Refresh Tokens, OAuth2 Grant Types

**Port:** 8086 | **Entry:** `module6-jwt-oauth2-advanced`

### 9.1 JWT Signing Algorithms

JWTs must be signed to prevent tampering. Spring Security (via jjwt) supports three algorithms:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    JWT SIGNING ALGORITHM COMPARISON                              │
│                                                                                  │
│  HS256 (HMAC-SHA256) — Symmetric                                                │
│  Auth Server ──── shared secret ────▶ Resource Server                          │
│  • One key to manage                                                             │
│  • All verifiers must share the secret — risk if any service is compromised     │
│  • Use when: single service, tightly controlled microservices                   │
│                                                                                  │
│  RS256 (RSA-SHA256) — Asymmetric                                                │
│  Auth Server (private key) → sign JWT → /.well-known/jwks.json (public key)   │
│  Resource Servers (public key) → verify JWT                                     │
│  • Private key never leaves auth server                                         │
│  • Resource servers only need public key (safe to distribute)                   │
│  • Key rotation: add new pair to JWKS, old tokens still verify                  │
│  • Use when: multi-service / microservices                                       │
│                                                                                  │
│  ES256 (ECDSA P-256) — Asymmetric                                               │
│  Same asymmetric benefits as RS256 but:                                          │
│  • 256-bit EC key ≈ 3072-bit RSA security                                       │
│  • 64-byte signature vs 256-byte for RSA-2048                                   │
│  • Faster signing/verification                                                   │
│  • Use when: mobile, IoT, token-size sensitive, FIPS compliance                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Live Endpoints:**
| Endpoint | Description |
|---|---|
| `GET /api/jwt-demo/hs256` | Generate HS256 token + security notes |
| `GET /api/jwt-demo/rs256` | Generate RS256 token + public JWK |
| `GET /api/jwt-demo/es256` | Generate ES256 token + EC public JWK |
| `GET /api/jwt-demo/.well-known/jwks.json` | JWK Set (both RSA + EC public keys) |
| `GET /api/jwt-demo/verify/rs256?token=...` | Verify an RS256 token |
| `GET /api/jwt-demo/comparison` | Algorithm comparison table |

### 9.2 JWK Set and Key Rotation

```
Key Rotation Flow (RS256/ES256):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1: Normal operation
  Auth Server signs JWT with key-id="rsa-key-1"
  JWKS: { keys: [{ kid: "rsa-key-1", ... }] }

Step 2: Generate new key pair
  JWKS: { keys: [{ kid: "rsa-key-1", ... }, { kid: "rsa-key-2", ... }] }
         ↑ old key still here (old tokens still validate)

Step 3: Start signing new tokens with rsa-key-2
  JWT header: { alg: "RS256", kid: "rsa-key-2" }
  Resource servers fetch JWKS → verify with correct key by kid

Step 4: Remove old key after expiry window
  JWKS: { keys: [{ kid: "rsa-key-2", ... }] }
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 9.3 Refresh Token Rotation with Theft Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│              REFRESH TOKEN LIFECYCLE                                 │
│                                                                      │
│  1. LOGIN                                                            │
│     → ACCESS token  (15 min, JWT, stateless)                        │
│     → REFRESH token (7 days, opaque random bytes, stored in DB)     │
│     → family_id = UUID (groups all tokens for this session)         │
│                                                                      │
│  2. ACCESS TOKEN EXPIRES                                             │
│     POST /auth/refresh { refreshToken }                             │
│       a. Look up in DB                                               │
│       b. Verify: not expired, not revoked                           │
│       c. Issue NEW access token                                      │
│       d. Issue NEW refresh token (same family_id)                   │
│       e. Mark OLD refresh token as REVOKED ← ROTATION               │
│                                                                      │
│  3. THEFT DETECTION                                                  │
│     If a revoked refresh token is presented again:                   │
│       → Someone is reusing an old token                             │
│       → REVOKE the ENTIRE family → force re-login on all devices    │
│                                                                      │
│  4. LOGOUT                                                           │
│     POST /auth/logout → revoke entire family                         │
│     POST /auth/logout-all → revoke ALL families for user            │
└─────────────────────────────────────────────────────────────────────┘

Why opaque refresh tokens (not JWT)?
  JWT: cannot be revoked without a blacklist (token is self-contained)
  Opaque: just flip a DB flag → instantly invalid
```

**Sequence Diagram — Refresh Token Rotation:**

![Refresh Token Rotation with Theft Detection](https://www.plantuml.com/plantuml/png/bLF1JXin4BtxAuPm0Gb4qXQf88781lOKgIZaMAcQs9F4MgyTx5aY527r8_g5V4bdlQIGIArKxSMUzsRUcndlJMACtDHE7V2IQeALG-jLggnVOSGQPgYhHGoDDwFWGeJ3SjX-7nY97Xlocc2Z08OnXlKRyzFeyzrvNu9ZEwUnzLI4Q2Zke_TYm6gxGi-xX8kl_U9YZx3lvguepyj2lIZ5bXt1XEQHqXAceI8Fay38DdXOMvROakOCjyIasw1Ig5bgzCQqi6nhP8AHi-Iv1vZ0wIq-P1PPYZcCNAdLko516odzGF5fIqZA8ECC4q6lit5RPCJCb78QJg_RooNSVtkOmXbA-faB2ncwH0KpCy6I24ipqnz3E9fZRTtpLJaupWoXI95BsA3Mb59ME87OzPrlLstUoz-qtfYmwLWVH6kCLQVP938dxoQANM5FQ_YdU27YFiWuWmobdPXaROVOLdLTQx80WVxBOdQ7BXAQv-pouBkVq9C8W-pDYjrkMb0Ejfux-I_zmP-tmNafaIGVJ7uDP7OwF4BdEbOIMblTmElFNt8-pPkImsCZOkPOgHloHdwVtm00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Refresh Token Rotation with Theft Detection

actor "Legitimate Client" as lc
actor "Attacker" as atk
participant "Auth Server" as as
database "Token DB" as db

lc -> as : POST /auth/login
as -> db : store RT_A (family=F1)
as --> lc : {accessToken, refreshToken=RT_A}

lc -> as : POST /auth/refresh {RT_A}
as -> db : mark RT_A used, store RT_B
as --> lc : {new accessToken, refreshToken=RT_B}

note over atk : Attacker stole RT_A

atk -> as : POST /auth/refresh {RT_A}
as -> db : RT_A already used!\nRevoke entire family F1
as --> atk : 401 Refresh token reuse detected
as --> lc : (all tokens revoked — re-login required)
@enduml
```

</details>

### 9.4 OAuth2 Grant Types

```
OAUTH2 GRANT TYPE DECISION TREE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Is there a USER involved?
  YES ──┬── Web/Mobile app? → Authorization Code + PKCE (RFC 7636)
        │                     Required for public clients (SPA, mobile)
        │                     PKCE prevents auth code interception
        │
        └── Device without browser? → Device Authorization Grant (RFC 8628)
                                       TV, CLI, IoT: user approves on phone

  NO  → Client Credentials
        Machine-to-machine, no user
        Microservices, cron jobs, background workers

REFRESH TOKEN (not standalone — used after any user-involved flow)
  Rotate refresh tokens to detect theft

DEPRECATED (do not use):
  Implicit Grant → removed in OAuth 2.1 (token in URL fragment = exposed)
  ROPC (Resource Owner Password) → removed in OAuth 2.1 (client handles passwords)

OAuth 2.1 changes:
  • PKCE required for ALL public clients
  • Exact redirect URI matching (no wildcards)
  • Refresh token rotation required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Live Endpoints:**
| Endpoint | Description |
|---|---|
| `POST /auth/login` | Login: returns access + refresh tokens |
| `POST /auth/refresh` | Rotate refresh token |
| `POST /auth/logout` | Revoke token family |
| `POST /auth/logout-all` | Revoke all sessions |
| `GET /api/oauth2-guide/authorization-code-pkce` | PKCE flow guide |
| `GET /api/oauth2-guide/client-credentials` | M2M guide |
| `GET /api/oauth2-guide/device-code` | Device flow guide |
| `GET /api/oauth2-guide/deprecated-grants` | Why implicit/ROPC removed |
| `GET /api/oauth2-guide/all-grants-summary` | Quick reference |

---

## 10. Module 7 — Advanced Security

**Port:** 8087 | **Entry:** `module7-advanced-security`

### 10.1 Custom AuthenticationProvider

```
ProviderManager (implements AuthenticationManager)
  │
  ├── CustomAuthenticationProvider  ← our custom provider
  │     ├── supports(UsernamePasswordAuthenticationToken.class) → true
  │     ├── loadUserByUsername(username)
  │     ├── passwordEncoder.matches(raw, encoded)
  │     └── bruteForceProtectionService.recordFailedAttempt / recordSuccess
  │
  └── (other providers can be chained in sequence)

Why extend AuthenticationProvider?
  • Add business rules before/after authentication
  • Integrate with external identity sources (LDAP, Active Directory)
  • Support custom token types (OTP, API key, certificate)
  • Wrap standard auth with additional checks (brute force, MFA, IP whitelist)
```

### 10.2 Brute Force Protection State Machine

![Brute Force Protection State Machine](https://www.plantuml.com/plantuml/png/bPB1IWCn48RlUOeHBwrGAAq5ArRQBTrJ1K4ykHvYTjg6PfDbTe85yUe3-8W-YSdQhMizYEnj_l_x_qcoquebiI-CEE4D5WYbaTgAQgjjAKaMy2JLTatEstpkZ2CuJMVnQpb20YEy283asBj8qb6QHCLHZhIV3iON_MGSfZCYzzmCvyF5g2zUXM3D1Y4X7r9JHmhXbXoZOkqitDLbDr9jj4KX7iuUeTUxXdjhdDfY3fSWbGeRC2Z2OCs5E6X7niehXLMryWQCMskRsGvXXO6CF5Bt9pbZng9aRTU1NKbjmhpXv9TMmHKKSjSLBUylL5eNRfhg24_uD_slbO_OvU5Mcex999O4C68ns7a6rWM6PopAhX3BxoCVwBgioSZinzixd0-6UxrDj7PjidDFCZvTPd5NQWfQHtfsFLzRG-4KRHv-m4y0)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Brute Force Protection State Machine

[*] --> Unlocked : account created

Unlocked --> Unlocked : successful login\n(reset counter)
Unlocked --> Attempting : failed login\n(attempts < max)
Attempting --> Attempting : another failure\n(attempts < max)
Attempting --> Unlocked : successful login\n(reset counter)
Attempting --> Locked : attempts == max\n(set lockout timestamp)

Locked --> Locked : login attempt\n→ 423 Locked
Locked --> Unlocked : lockout duration\nexpired (auto-unlock)
@enduml
```

</details>

**Configuration (application.properties):**
```properties
security.max-login-attempts=5
security.lockout-duration-minutes=15
```

### 10.3 Role Hierarchy

![Role Hierarchy: ADMIN > MANAGER > USER](https://www.plantuml.com/plantuml/png/ZP7HIyCm4CRVxwyuyMqmEWJ1xM6idQqARaB5vt5hZZMkJSerVP3f_swZ6qlL1mc4t9VVVT-5B5f7uhgwWWjNSitOLAGDj7jj6XAgSKl5VYUsCsffAojucSL-1OJTldBXy028oKyuJRBhBF4tLXJBKRsQtaoIANm0EEqgnjpssxrc8IdAjnd6jwk7DSvn5Q_ZkpJlJo_FQGvmJCgV7jFDD-D38sfqHAhM9XgDJdLDXdOiWTArWv8wfLtOm7wUCE6KVlYtvsyFF_VPu4yyUCru_3uVPizGcv95knO6-fdyIWWmMB1H_Nz-0W00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Role Hierarchy: ADMIN > MANAGER > USER

object ROLE_ADMIN {
  /api/admin/**
  /api/manager/**
  /api/user/**
  /api/audit/**
  /api/me
}

object ROLE_MANAGER {
  /api/manager/**
  /api/user/**
  /api/me
}

object ROLE_USER {
  /api/user/**
  /api/me
}

ROLE_ADMIN --|> ROLE_MANAGER : inherits
ROLE_MANAGER --|> ROLE_USER : inherits
@enduml
```

</details>

**Key Spring Security 6.2 limitation:** `hasRole()` in `authorizeHttpRequests()` does NOT auto-apply role hierarchy. Only `@PreAuthorize` with an explicit `MethodSecurityExpressionHandler` bean does.

```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl h = new RoleHierarchyImpl();
    h.setHierarchy("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER");
    return h;
}

@Bean
public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy h) {
    DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
    handler.setRoleHierarchy(h);
    return handler;
}
```

### 10.4 Security Headers

| Header | Value | Protects Against |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | SSL stripping, MITM |
| `Content-Security-Policy` | `default-src 'self'` | XSS, data injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=()` | Feature abuse |

```java
http.headers(h -> h
    .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true))
    .frameOptions(f -> f.deny())
    .contentTypeOptions(c -> {})
    .referrerPolicy(r -> r.policy(STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
    .permissionsPolicy(p -> p.policy("camera=(), microphone=()"))
)
```

### 10.5 Security Events and Audit Logging

![Spring Security Event Flow — Module 7](https://www.plantuml.com/plantuml/png/bPHTJzim68Nl_IkyxgPeusCmjC75HXBI2ItGYhJNbMk_BLPTE_D7EuJuxtkTf9HMW8OgvSBdUUrpJfnUEC-i3mj5FlWxM02j59EQkBdK5RDiGIUCpsVM12qoeuob7tj9_3qZ7Fm9e3dG1q9fOgrPjUHnTfAV7k5Y8QTGI0sfiGBihZf00vBBYcc_3PnzFqhFTe1TDtdQE-sbv94GBxq2MbPMwXajWGSh_JtDbw0zxIcpejrh8m8Yt_O8OTpZTAOaggJQx4yxWtuvf8Si-Bj3PMPIToXp5AfjA0lEcqM2qC2QfKJFDSRP3fVQuA5dB8SIx59ogB79r6rZILKfoPcNHjT-1s6YfBjhTwt2P1jVXwlPGZeFkaKTg9sTWv3--Tai22AOPnFce9KBCwENQQsA2I5DANJ_1wQcv_GXEB2QBU0phPXpAtn3ZmGLr34k0h4g78Z-eRj7uY9gc14rwGh3vo2wwqtsVfAex3zDJvboGDPJpPeoJ8nmW7wYIx1oUZze3yRtfZnrWNDm3Yz6EuK5uLJLb4QJZH_iispWkYgSY2XEO4yuyQIYRLgleOG5rHPctQB_w-fcN8woB2_BI4G92H5FkxefyzjXN99-ZFJQpRgsRHVKcpbePA11sewntLeufnsuFpWuw62pM0T-Su9o2o9kWFriaZQjMk1OHez91IBn7XQLhnFyHnrnA5X8cSWs-xzIJik-LKulkIf6j_bxozav_Y-7AffxeP-lHr-QIXZd-DLxF3lUftU5RQxWAo7R-_bYnYJB-gERuRZePx_pot4JEHaEy-l1yBsHMnDlHJq-QIa26g_w1JxnV_aV)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Spring Security Event Flow (Module 7)

actor Client
participant "POST /auth/login" as ep
participant "CustomAuthProvider" as cap
participant "BruteForceService" as bfs
participant "ApplicationEventPublisher" as pub
participant "SecurityEventListener" as sel
participant "AuditService" as aud
database "AuditLog DB" as db

Client -> ep : {username, password}
ep -> cap : authenticate()
cap -> bfs : isLocked(username)?
bfs --> cap : false

cap -> cap : loadUser + verifyPassword

alt success
  cap -> pub : publish AuthenticationSuccessEvent
  pub -> sel : onSuccess()
  sel -> aud : log(LOGIN_SUCCESS)
  aud -> db : INSERT audit_log
  cap --> ep : Authentication token
  ep --> Client : {token: "ey..."}
else bad credentials
  cap -> bfs : recordFailedAttempt()
  cap -> pub : publish AuthenticationFailureBadCredentialsEvent
  pub -> sel : onFailure()
  sel -> aud : log(LOGIN_FAILURE)
  aud -> db : INSERT audit_log
  cap --> ep : BadCredentialsException
  ep --> Client : 401
else account locked
  cap -> pub : publish AuthenticationFailureLockedEvent
  pub -> sel : onLocked()
  sel -> aud : log(ACCOUNT_LOCKED_LOGIN_ATTEMPT)
  aud -> db : INSERT audit_log
  cap --> ep : LockedException
  ep --> Client : 423 Locked
end
@enduml
```

</details>

**Key Spring Security events:**
| Event | When fired |
|---|---|
| `AuthenticationSuccessEvent` | Login succeeded |
| `AuthenticationFailureBadCredentialsEvent` | Wrong password / unknown user |
| `AuthenticationFailureLockedEvent` | Account is locked |
| `AuthenticationFailureDisabledEvent` | Account is disabled |
| `AuthenticationFailureExpiredEvent` | Credentials/account expired |

### 10.6 @AuthenticationPrincipal

```java
// Old way — verbose, couples to security infrastructure:
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
UserDetails user = (UserDetails) auth.getPrincipal();

// New way — clean, declarative, works with @WithMockUser in tests:
@GetMapping("/api/me")
public ResponseEntity<?> profile(@AuthenticationPrincipal UserDetails currentUser) {
    return ResponseEntity.ok(Map.of("username", currentUser.getUsername()));
}

// Custom UserDetails:
@GetMapping("/api/me")
public ResponseEntity<?> profile(@AuthenticationPrincipal CustomUser user) {
    return ResponseEntity.ok(user.getFullName()); // cast to your type
}

// SpEL for anonymous-safe access:
public ResponseEntity<?> data(@AuthenticationPrincipal(
    expression = "#this == 'anonymousUser' ? null : principal") UserDetails user) {
```

### 10.7 Password Policy

The `PasswordPolicyService` enforces NIST SP 800-63B guidelines:
- Minimum 8 characters (up to 72 for bcrypt)
- At least one uppercase, lowercase, digit, special character
- Cannot contain username
- Cannot be a common password (top 15 checked)
- No three sequential identical or ascending/descending characters
- Strength score (0–5)

**Endpoint:** `POST /api/public/password-check` — public, no auth required.

### 10.8 ACL (Access Control Lists) — Conceptual Guide

ACL provides **domain object security** — per-object, per-user permissions beyond RBAC:

```
RBAC (Role-Based):        hasRole("ADMIN") → can access ALL documents
ACL (Object-Based):       Alice can READ document 123
                          Bob can READ + WRITE document 123
                          Carol is OWNER of document 123 (READ + WRITE + DELETE)

Spring Security ACL tables:
  acl_class          — maps Java class to numeric ID
  acl_sid            — maps principal/role to numeric ID
  acl_object_identity — maps each object instance to class + object ID
  acl_entry          — the permission entries (who, what object, what permission)

Usage:
  @PreAuthorize("hasPermission(#doc, 'READ')")
  public Document getDocument(Document doc) { ... }
```

See `GET /api/public/concepts/acl` for a full implementation guide.

**Live Endpoints (Module 7):**
| Endpoint | Auth Required | Description |
|---|---|---|
| `POST /auth/login` | None | Login with brute force protection |
| `GET /api/me` | Any | @AuthenticationPrincipal demo |
| `GET /api/user/data` | USER+ | Role hierarchy: USER/MANAGER/ADMIN |
| `GET /api/manager/dashboard` | MANAGER+ | Role hierarchy: MANAGER/ADMIN |
| `GET /api/admin/dashboard` | ADMIN | Admin only |
| `GET /api/audit/recent` | ADMIN | Security audit log |
| `POST /api/public/password-check` | None | Password policy check |
| `GET /api/public/concepts/role-hierarchy` | None | Role hierarchy guide |
| `GET /api/public/concepts/security-headers` | None | Security headers guide |
| `GET /api/public/concepts/brute-force-protection` | None | Brute force strategies |
| `GET /api/public/concepts/acl` | None | ACL implementation guide |
| `GET /api/public/concepts/session-management` | None | Session management guide |
| `GET /api/public/concepts/authentication-principal` | None | @AuthenticationPrincipal guide |

---

## 11. Security State Diagram

Full security lifecycle for a request:

![Spring Security Request State Machine](https://www.plantuml.com/plantuml/png/XPDHIyCm58NVyokk-2OCQkT0zo1hv_eYecpu93waoNKBQvDwaqvK_EycNNLTDv6ytNE-t7C2cLZ7oTLbmKxS2ak4gk1ACxjMkkB4IyYvM2_9r5fEJM48JhCad8x3t-0GFXb0slVEqcoKfK4n997QQNnr6QLNVfeGcRUVuNGu6qNiYp6dN86mg4Zf9InGrAJSEypnjKRhOD5ik-DYfJGozdJs38F1DJngNli2sYdXTGbZe1RWH6g3bh6-9M39RXAsZK4GoZ3WXGLRvwLotifwjXxPhEk26rwe_o1bTCPLqR0vbrsU7RK5FhGTmqLqtlOrf3vyF9OSBRPLFR3YTcxycueLYZLKt5gqnnWXqDeRrEe8zU9JUAXhwIOQGcOeLz9tsCPfbmVF0vb0RH-uHAz9K7fZrZvwHskinhfVUkScT3Lfo_Rb0CpHLaRB9l1aNsvx7ZBT4l4XTzWq_hFgRltE4KSHtDyoDa4j_SVw1W00)

<details>
<summary>📐 PlantUML Source</summary>

```plantuml
@startuml
!theme plain
title Spring Security Request State Machine

[*] --> Unauthenticated : request arrives

Unauthenticated --> Authenticating : credentials submitted
Authenticating --> Authenticated : credentials valid
Authenticating --> AuthenticationFailed : bad credentials
AuthenticationFailed --> [*] : 401 Unauthorized

Authenticated --> Authorized : hasRole check passes
Authenticated --> AccessDenied : hasRole check fails
AccessDenied --> [*] : 403 Forbidden

Authorized --> Processing : method invoked
Processing --> PostAuthorize : method returns
PostAuthorize --> Responded : @PostAuthorize passes
PostAuthorize --> AccessDenied2 : @PostAuthorize fails
AccessDenied2 --> [*] : 403 Forbidden
Responded --> [*] : 200 OK
@enduml
```

</details>

---

## 12. CSRF Protection

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

## 13. Password Encoding

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

## 14. Quick Reference

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

## 15. Running Each Module

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

### Module 6 — JWT Signing, Refresh Tokens, OAuth2 Grant Types
```bash
cd module6-jwt-oauth2-advanced
mvn spring-boot:run
# Swagger: http://localhost:8086/swagger-ui.html

# Login to get tokens:
curl -s -X POST http://localhost:8086/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"pass123"}' | jq .

# View JWT signing algorithm demos:
curl http://localhost:8086/api/jwt-demo/hs256 | jq .
curl http://localhost:8086/api/jwt-demo/rs256 | jq .
curl http://localhost:8086/api/jwt-demo/es256 | jq .

# JWKS endpoint:
curl http://localhost:8086/api/jwt-demo/.well-known/jwks.json | jq .

# OAuth2 grant type guides (no auth needed):
curl http://localhost:8086/api/oauth2-guide/authorization-code-pkce | jq .
curl http://localhost:8086/api/oauth2-guide/client-credentials | jq .
curl http://localhost:8086/api/oauth2-guide/device-code | jq .
curl http://localhost:8086/api/oauth2-guide/deprecated-grants | jq .
```

### Module 7 — Advanced Security
```bash
cd module7-advanced-security
mvn spring-boot:run
# Swagger: http://localhost:8087/swagger-ui.html

# Login (with brute force protection):
curl -s -X POST http://localhost:8087/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice@1234"}' | jq .

# Store the token:
TOKEN=$(curl -s -X POST http://localhost:8087/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@1234"}' | jq -r .token)

# @AuthenticationPrincipal demo:
curl -H "Authorization: Bearer $TOKEN" http://localhost:8087/api/me | jq .

# Role hierarchy: admin can access manager endpoint:
curl -H "Authorization: Bearer $TOKEN" http://localhost:8087/api/manager/dashboard | jq .

# Password policy check (no auth needed):
curl -s -X POST http://localhost:8087/api/public/password-check \
  -H 'Content-Type: application/json' \
  -d '{"password":"weak","username":"alice"}' | jq .

# Security concept guides:
curl http://localhost:8087/api/public/concepts/role-hierarchy | jq .
curl http://localhost:8087/api/public/concepts/security-headers | jq .
curl http://localhost:8087/api/public/concepts/brute-force-protection | jq .
curl http://localhost:8087/api/public/concepts/acl | jq .

# Audit log (ADMIN only):
curl -H "Authorization: Bearer $TOKEN" http://localhost:8087/api/audit/recent | jq .
```

### Run All Tests
```bash
# From parent directory (skips OAuth2 module which needs a real provider):
mvn test -pl !module4-oauth2
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
├── module5-method-security/         ← @PreAuthorize, CORS, Exceptions
│   ├── service/DocumentService.java
│   ├── service/DocumentPermissionEvaluator.java
│   ├── config/MethodSecurityConfig.java
│   └── exception/SecurityExceptionHandler.java
│
├── module6-jwt-oauth2-advanced/     ← JWT signing, Refresh tokens, OAuth2 grant types
│   ├── util/{AccessTokenUtil,JwtSigningUtil}.java
│   ├── service/RefreshTokenService.java       ← rotation + theft detection
│   ├── entity/RefreshToken.java
│   ├── controller/{TokenController,JwtSigningDemoController,OAuth2GrantTypesController}.java
│   └── filter/JwtAuthFilter.java
│
└── module7-advanced-security/       ← Brute force, role hierarchy, security headers, audit
    ├── provider/CustomAuthenticationProvider.java
    ├── service/{BruteForceProtectionService,AuditService,PasswordPolicyService}.java
    ├── event/SecurityEventListener.java
    ├── entity/{User,AuditEvent}.java
    ├── config/{SecurityConfig,PasswordEncoderConfig,DataInitializer}.java
    └── controller/{AuthController,UserController,AuditController,SecurityConceptsController}.java
```
