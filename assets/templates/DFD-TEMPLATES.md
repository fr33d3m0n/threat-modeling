<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# Data Flow Diagram Templates for STRIDE Threat Modeling

Source: Adapted from architecture-diagrams skill

## Mermaid DFD Templates

### Template 1: Basic Web Application DFD

```mermaid
graph LR
    subgraph "External"
        User[User<br/>External Interactor]
        Admin[Admin<br/>External Interactor]
    end

    subgraph "Trust Boundary: DMZ"
        Gateway[API Gateway<br/>Process]
    end

    subgraph "Trust Boundary: Application"
        Auth[Auth Service<br/>Process]
        App[App Service<br/>Process]
    end

    subgraph "Trust Boundary: Data"
        UserDB[(User DB<br/>Data Store)]
        AppDB[(App DB<br/>Data Store)]
        Cache[(Cache<br/>Data Store)]
    end

    User -->|HTTP/HTTPS<br/>Data Flow| Gateway
    Admin -->|HTTP/HTTPS<br/>Data Flow| Gateway
    Gateway -->|Auth Request| Auth
    Gateway -->|API Request| App
    Auth -->|Query/Update| UserDB
    App -->|Query/Update| AppDB
    App -->|Read/Write| Cache
```

### Template 2: Microservices Architecture DFD

```mermaid
graph TB
    subgraph "External Interactors"
        Client[Web/Mobile Client]
        Partner[Partner API]
    end

    subgraph "Trust Boundary: Edge"
        LB[Load Balancer]
        GW[API Gateway]
    end

    subgraph "Trust Boundary: Services"
        UserSvc[User Service]
        OrderSvc[Order Service]
        PaymentSvc[Payment Service]
        NotifySvc[Notification Service]
    end

    subgraph "Trust Boundary: Data Tier"
        UserDB[(User DB)]
        OrderDB[(Order DB)]
        Queue[Message Queue]
    end

    subgraph "External Services"
        Stripe[Stripe API]
        Email[Email Provider]
    end

    Client --> LB
    Partner --> LB
    LB --> GW
    GW --> UserSvc
    GW --> OrderSvc
    GW --> PaymentSvc
    UserSvc --> UserDB
    OrderSvc --> OrderDB
    OrderSvc --> Queue
    PaymentSvc --> Stripe
    Queue --> NotifySvc
    NotifySvc --> Email
```

### Template 3: Data Flow with Security Controls

```mermaid
graph LR
    User[User Action] --> Frontend[Frontend App]
    Frontend --> Validation{Input<br/>Validation}
    Validation -->|Invalid| Error[Show Error]
    Validation -->|Valid| API[API Request]
    API --> Auth{Authenticated?}
    Auth -->|No| Unauthorized[401 Response]
    Auth -->|Yes| Authz{Authorized?}
    Authz -->|No| Forbidden[403 Response]
    Authz -->|Yes| Service[Business Service]
    Service --> Database[(Database)]
    Database --> Response[API Response]
    Response --> Frontend
```

### Template 4: Authentication Flow DFD

```mermaid
sequenceDiagram
    actor User
    participant Web as Web App
    participant Gateway as API Gateway
    participant Auth as Auth Service
    participant DB as User Database
    participant Token as Token Store

    User->>Web: Login Request
    Web->>Gateway: POST /auth/login
    Gateway->>Auth: Validate Credentials
    Auth->>DB: Query User
    DB-->>Auth: User Data
    Auth->>Auth: Verify Password Hash
    Auth->>Token: Generate Tokens
    Token-->>Auth: Access + Refresh Token
    Auth-->>Gateway: Tokens
    Gateway-->>Web: Set Cookies
    Web-->>User: Login Success

    Note over User,Token: Token includes: userId, role, exp, iat
```

## PlantUML DFD Templates

### Template 5: Component-Level DFD

```plantuml
@startuml
!define PROCESS circle
!define DATASTORE database
!define EXTERNAL actor
!define TRUSTBOUNDARY rectangle

EXTERNAL "User" as user
EXTERNAL "Admin" as admin

TRUSTBOUNDARY "DMZ" {
  PROCESS "API Gateway" as gw
  PROCESS "WAF" as waf
}

TRUSTBOUNDARY "Application Tier" {
  PROCESS "Auth Service" as auth
  PROCESS "Business Logic" as biz
  PROCESS "Report Generator" as report
}

TRUSTBOUNDARY "Data Tier" {
  DATASTORE "User DB" as userdb
  DATASTORE "App DB" as appdb
  DATASTORE "File Storage" as files
}

user --> waf : HTTPS
admin --> waf : HTTPS/VPN
waf --> gw : Forward
gw --> auth : Auth Request
gw --> biz : API Request
auth --> userdb : Query/Update
biz --> appdb : CRUD
biz --> files : Read/Write
report --> appdb : Read Only
@enduml
```

## STRIDE Annotation Conventions

When annotating DFD for STRIDE analysis:

### Color Coding
- **Red**: High-risk data flows (PII, credentials)
- **Orange**: Medium-risk (business data)
- **Blue**: Low-risk (public data)

### Element Labeling Format
```
[ElementType] ElementName
Properties:
- authenticates: true/false
- encrypts: true/false
- validates_input: true/false
```

### Trust Boundary Types
1. **Network**: Internet/DMZ/Internal
2. **Process**: Container/VM/Host
3. **User**: Anonymous/Authenticated/Admin

### Data Flow Annotations
```
Source --> Target : Protocol/Encryption
                    Data: [SensitivityLevel]
```

## Threat ID Format

Pattern: `T-{STRIDE}-{ElementID}-{Sequence}`

Examples:
- `T-S-GW-001`: Spoofing threat on Gateway #1
- `T-T-DF1-002`: Tampering threat on DataFlow #2
- `T-I-DS1-001`: Information Disclosure on DataStore #1
