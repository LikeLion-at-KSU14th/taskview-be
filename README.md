# Needex BE

AI가 제안한 View 계획을 결정론적으로 검증하고, 사용자·보안 세션·소유자 승인·Task View 증적을 PostgreSQL에 영구 저장하는 API입니다. 전체 Task View 계약은 JSONB로 보존하면서 상태·목적·대상·TTL은 별도 컬럼으로 인덱싱합니다.

```mermaid
flowchart LR
    U["사용자"] --> FE["taskview-fe<br/>Next.js"]
    FE --> BE["taskview-be<br/>정책 · 승인 · 증적"]
    BE --> AI["taskview-ai<br/>단일 Agent"]
    AI --> O["Ollama<br/>qwen3.5:9b"]
    BE --> P["Policy Engine"]
    BE --> M["Materializer"]
    BE --> A["Audit / Evidence"]
```

FE는 AI를 직접 호출하지 않습니다. 따라서 모델의 제안은 항상 BE의 정책 검사와 소유자 승인 경계를 통과합니다.

## 실행

AI 서버(`localhost:8100`)를 먼저 실행한 뒤:

```bash
make install
make db
make dev
```

AI 서버 없이 계약을 확인할 때는:

```bash
TASKVIEW_BE_FAKE_AI=true make dev
```

API 문서는 `/docs`, 생존 확인은 `/health`, PostgreSQL·메일 전달 준비 상태는 `/ready`입니다.

### 로컬 메일 확인

Compose는 개발 토큰 노출을 기본으로 끄고 Mailpit SMTP를 사용합니다. 인증·재설정·초대 메일은 [http://localhost:8025](http://localhost:8025)에서 확인합니다.

```bash
docker compose up --build
```

호스트에서 `make dev`로 직접 실행할 때는 `.env.example`을 참고해 Fernet 키와 SMTP를 설정해야 합니다. `TASKVIEW_EXPOSE_DEV_TOKENS=true`는 명시적인 테스트에서만 사용하며, 이 경우에도 outbox 저장 값은 항상 암호문입니다.

## 세 저장소 함께 실행

호스트에서 `ollama serve`와 `ollama pull qwen3.5:9b`를 실행한 뒤 이 저장소에서:

```bash
docker compose up --build
```

### 공식 공개 데이터 동기화

일반 체험 계정은 별도 API key 없이 FCC Consumer Complaints, NYC 311, NHTSA Vehicle Safety Complaints의 공식 공개 스냅샷을 사용합니다. 동기화는 원본 행을 보관하지 않고 전화번호·정확한 주소/좌표·VIN·민원 원문을 정규화 단계에서 제거합니다.

```bash
TASKVIEW_DATABASE_URL=postgresql://taskview:taskview@127.0.0.1:54329/taskview \
  uv run python scripts/sync_public_demo.py
```

성공 시 `public_demo_source_snapshots`에 출처·라이선스·시각·행 수·SHA-256이, `public_demo_records`에는 허용된 안전 필드와 해시 식별자만 저장됩니다. Task View는 20건 이상 그룹만 materialize하며 응답의 `data_origin`은 `public_live`입니다. 인터넷/API 장애 시 기존 스냅샷을 삭제하지 않습니다.

Compose는 형제 디렉터리의 `taskview-ai`, `taskview-fe`와 Mailpit을 실행하고 AI 컨테이너가 macOS 호스트의 Ollama에 연결하도록 설정되어 있습니다. Apple Silicon의 Metal 가속을 사용하기 위해 Ollama 자체는 호스트에서 실행합니다.

## 핵심 API

- `POST /v1/auth/signup` — 이메일 인증 대기 없이 요청자 계정 생성 및 세션 발급
- `POST /v1/auth/login` — 로그인 및 세션 발급
- `GET /v1/auth/me` — 현재 사용자 조회
- `POST /v1/auth/session/refresh` — 기존 세션 폐기 후 새 세션 발급
- `POST /v1/auth/logout` — 현재 세션 폐기
- `POST /v1/workspace-invitations/accept` — 로그인 이메일과 일치하는 일회성 초대 수락
- `GET /v1/taskviews` — 요청자는 현재 workspace의 자신의 View, 소유자·관리자는 해당 workspace View 조회
- `POST /v1/taskviews/preview` — 목적을 계획·정책·미리보기로 컴파일
- `POST /v1/taskviews/{id}/decision` — 데이터 소유자·관리자 승인/거절
- `GET /v1/taskviews/{id}` — 현재 상태 조회
- `POST /v1/taskviews/{id}/refine` — 목적 보완 및 선택적 TTL 변경 후 재검토
- `GET /v1/taskviews/{id}/evidence` — 승인된 View의 Evidence Contract
- `GET /v1/taskviews/{id}/data.csv` — 승인·TTL·최소 그룹 기준을 재검사한 전체 안전 집계 CSV
- `POST /v1/ui/data-sources/test` — allowlist·TLS·read-only 연결 검증
- `POST /v1/ui/data-sources/scan` — raw row 없이 `information_schema` catalog 스캔
- `POST /v1/ui/data-sources/scan/complete` — 만료 전 일회성 scan job을 workspace source로 확정

## 인증과 권한

- 비밀번호는 Argon2 권장 설정으로 단방향 해시합니다.
- 로그인 토큰은 384-bit 난수이며 DB에는 SHA-256 해시만 보관합니다.
- 세션은 기본 7일 후 만료되고 로그아웃·갱신 시 즉시 폐기됩니다.
- 5회 연속 로그인 실패 시 기본 15분 동안 계정을 잠급니다.
- 권한은 전역 사용자 역할이 아니라 `workspace_memberships.role`로 판정합니다.
- `requester`는 자신의 View만 볼 수 있고, 해당 workspace의 `data_owner`와 `admin`만 제출된 요청을 승인할 수 있습니다.
- 소유자·관리자 목록과 상세 응답에는 요청자 이름·이메일이 포함되어 동일 목적 요청도 구분할 수 있습니다.
- API는 존재 여부 노출을 막기 위해 다른 사용자의 View를 `404`로 응답합니다.
- 승인·보완 상태 전이는 조건부 갱신하며, 승인된 Evidence는 다시 수정할 수 없습니다.
- 데이터 소스 호스트는 DNS 이름과 해석된 모든 IP가 각각 allowlist를 통과해야 하며, 실제 연결 peer도 다시 검증합니다.
- 운영 기본값은 외부 DB 연결을 전부 거부하고 TLS와 인증서 검증을 요구합니다. Compose의 `postgres`/`172.16.0.0/12`/TLS 해제는 로컬 개발 전용입니다.
- 스캔 세션은 `transaction_read_only=on`을 강제하고 `information_schema`만 조회하며 raw row는 저장하거나 반환하지 않습니다.

프론트엔드는 원문 세션 토큰을 JavaScript에 전달하지 않고 HttpOnly·SameSite 쿠키에만 저장합니다. 프로덕션에서는 Secure 속성도 활성화됩니다.

## PostgreSQL 저장 구조

- `users` — 정규화 이메일, Argon2 해시, 역할, 잠금·로그인 상태
- `auth_sessions` — 토큰 해시, 만료·마지막 사용·폐기 시각
- `auth_delivery_outbox` — Fernet 암호화 전달 토큰, 재시도·backoff·전송/실패 상태
- `workspace_invitations` — 이메일·workspace 역할·일회성 초대 토큰 해시
- `data_source_scan_jobs` — workspace·생성자·만료·일회성 상태, metadata catalog와 임시 암호문
- `workspace_data_sources` — 연결 metadata, field 통계, catalog JSONB와 Fernet 암호화 credential
- `public_demo_source_snapshots` — 공식 출처·라이선스·동기화 시각·행 수·내용 해시
- `public_demo_records` — 직접 식별자를 제거한 공개 데이터 안전 스냅샷
- `task_views.id` — Task View 식별자
- `status`, `purpose`, `audience`, `ttl_days` — 조회·운영용 컬럼
- `payload JSONB` — 계획, 정책 결과, 미리보기, 승인 및 Evidence Contract 전체
- `created_at`, `updated_at` — 생성 및 갱신 시각

애플리케이션 시작 시 테이블과 조회 인덱스를 멱등적으로 생성합니다. Docker 데이터는 `taskview_postgres_data` volume에 유지됩니다.

데이터 소스 연결을 운영에서 활성화하려면 `.env.example`의 `TASKVIEW_DATA_SOURCE_ALLOWED_HOSTNAMES`, `TASKVIEW_DATA_SOURCE_ALLOWED_CIDRS`, TLS/CA 설정과 별도 `TASKVIEW_DATA_SOURCE_ENCRYPTION_KEY`를 비밀 저장소에서 주입해야 합니다. DSN과 비밀번호 평문은 DB, API 응답 또는 오류에 기록하지 않습니다. scan job은 기본 15분 후 만료되며 완료 또는 만료 시 job credential 암호문을 즉시 삭제합니다.

## 운영 전 교체할 부분

- 샘플 `materializer.py` → 읽기 전용 웨어하우스 작업 큐
- 로컬 계정 → 사내 SSO 또는 IdP 연동 및 이메일 검증/복구
- 단일 프로세스 감사 정보 → append-only audit store
## API key

Workspace `admin`만 설정 API에서 key를 목록·생성·폐기할 수 있습니다. secret은 생성 응답에 한 번만 노출되고 DB에는 SHA-256 hash와 prefix만 저장됩니다. 기본 TTL은 90일이며 요청 가능한 범위는 1~365일입니다.

```bash
# ADMIN_SESSION_TOKEN은 로그인으로 발급받은 admin 세션의 예시 placeholder입니다.
curl -X POST http://localhost:8200/v1/ui/settings/integrations/keys \
  -H "Authorization: Bearer $ADMIN_SESSION_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"analytics-reader","scopes":["taskviews:analytics:read"],"expiresInDays":90}'

# 응답의 secret은 이 시점에만 복사할 수 있습니다.
curl http://localhost:8200/v1/taskviews/VIEW_ID/analytics \
  -H "Authorization: Bearer $TASKVIEW_API_KEY"

# 즉시 폐기
curl -X DELETE http://localhost:8200/v1/ui/settings/integrations/keys/KEY_ID \
  -H "Authorization: Bearer $ADMIN_SESSION_TOKEN"
```

지원 scope와 허용 endpoint는 일대일로 대응합니다.

| scope | 허용 endpoint |
|---|---|
| `taskviews:artifacts:read` | `GET /v1/taskviews/{id}/artifacts` |
| `taskviews:data:read` | `GET /v1/taskviews/{id}/data` |
| `taskviews:analytics:read` | `GET /v1/taskviews/{id}/analytics` |

API key는 workspace에 고정된 read-only credential입니다. UI·관리·승인·쓰기 endpoint에는 사용할 수 없고, 다른 workspace는 `404`, scope 부족은 `403`, 승인 전 출력은 `409`, Evidence TTL 만료는 `410`, 만료·폐기된 key는 `401`입니다. `dashboard` 전용 View는 API key로 읽을 수 없습니다. `last_used_at`은 scope, workspace, 승인, 출력 형태와 TTL을 모두 통과한 성공 응답 직전에만 revoke/expiry를 원자적으로 재검사하며 갱신합니다.

## Data source scan 보안 경계

운영 source scan을 켜려면 다음 조건을 모두 만족해야 합니다.

1. 입력 hostname이 `TASKVIEW_DATA_SOURCE_ALLOWED_HOSTNAMES`에 정확히 있어야 합니다.
2. DNS가 해석한 **모든 IP**가 `TASKVIEW_DATA_SOURCE_ALLOWED_CIDRS`에 포함되어야 합니다.
3. 연결 후 실제 socket peer IP를 다시 검사해 DNS rebinding/우회 연결을 차단합니다.
4. 운영에서는 `TASKVIEW_DATA_SOURCE_REQUIRE_TLS=true`, `TASKVIEW_DATA_SOURCE_VERIFY_TLS=true`와 신뢰할 CA 파일을 사용합니다.
5. 연결 세션은 `transaction_read_only=on`을 강제하고 `information_schema` metadata만 읽습니다.
6. raw row는 조회·저장·API 반환하지 않으며, DSN/credential은 별도 Fernet key로 암호화합니다.

Compose의 `postgres`, `172.16.0.0/12`, TLS 해제는 로컬 스캔 검증 전용이며 운영에 복사하면 안 됩니다.

## Materializer와 준비 중 기능

공식 공개 데이터 계획은 PostgreSQL 안전 스냅샷에서 실제 집계되어 `data_origin="public_live"`로 반환됩니다. 기존 호환 계획이나 동기화되지 않은 테스트 환경만 결정론적 `synthetic_demo`를 사용합니다. 조직이 연결한 임의 warehouse의 raw row materialization과 작업 큐는 아직 별도 구현이 필요합니다. FE에서 준비 중으로 비활성화한 Audit 기간/CSV, Evidence 상세 계약, source 재스캔·사용 내역, workspace 나가기·삭제도 아직 운영 기능이 아닙니다.

## 운영 환경 체크리스트

- `TASKVIEW_BE_FAKE_AI=false`, `TASKVIEW_EXPOSE_DEV_TOKENS=false`, `TASKVIEW_MAIL_WORKER_ENABLED=true`를 유지합니다.
- `TASKVIEW_DATABASE_URL`, `TASKVIEW_AI_URL`, `TASKVIEW_PUBLIC_WEB_URL`을 운영 주소로 변경합니다.
- `TASKVIEW_DELIVERY_ENCRYPTION_KEY`와 `TASKVIEW_DATA_SOURCE_ENCRYPTION_KEY`를 환경별로 새로 생성해 비밀 저장소에서 주입합니다. Compose 기본 key를 재사용하지 않습니다.
- 운영 SMTP host/port/credential과 TLS 또는 STARTTLS를 설정합니다. Mailpit은 로컬 전용입니다.
- source hostname/CIDR/CA는 필요한 값만 최소 허용하고 PostgreSQL 계정 자체도 read-only로 제한합니다.

## 검증

```bash
make test
uv run ruff format --check .
uv run ruff check .
git diff --check
docker compose config --quiet
```

호스트 published port가 불안정한 환경에서는 PostgreSQL 테스트와 E2E를 `taskview-be_default` Docker 네트워크 내부에서 실행합니다.

## 독립 Docker 배포

이 저장소는 PostgreSQL과 BE만 독립적으로 배포합니다. AI는 다른 머신의 `taskview-ai` URL로 연결하고 FE 소스는 필요하지 않습니다.

```bash
cp .env.deploy.example .env.deploy
# PostgreSQL 비밀번호, 두 Fernet key, SMTP, FE URL, AI URL/공유 비밀 설정
./scripts/deploy.sh
```

핵심 연결 값:

- `TASKVIEW_AI_URL=https://ai.example.com`: 별도 AI 서버 주소
- `TASKVIEW_AI_SHARED_SECRET`: AI 서버와 동일한 무작위 값
- `TASKVIEW_PUBLIC_WEB_URL=https://taskview.example.com`: 비밀번호 복구·초대 링크에 사용할 FE 주소
- `TASKVIEW_CORS_ORIGINS`: 허용할 FE origin 목록

PostgreSQL은 외부 포트를 열지 않고 Compose 내부 네트워크에서만 BE에 연결됩니다. 신규 가입의 이메일 인증은 기본적으로 사용하지 않습니다. 운영 SMTP가 설정되지 않으면 비밀번호 복구와 워크스페이스 초대 메일은 정상 동작하지 않으므로 해당 기능을 사용할 때 실제 SMTP 값을 입력하세요.
