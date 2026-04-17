# ⚠️ TEST FILE — CodeGuard AI v8.0 IaC Scanner (Dockerfile)
# Every violation below should trigger a CG_IAC_DOCKER_* finding.
# Open this file in Windsurf with CodeGuard installed.

# CG_IAC_DOCKER_001 — :latest tag (unpinned, non-reproducible builds)
FROM node:latest

# CG_IAC_DOCKER_002 — no USER instruction (container runs as root, CIS-Docker 4.1)
# A safe Dockerfile would have: USER node

WORKDIR /app

# CG_IAC_DOCKER_003 — curl | sh (remote script execution, supply-chain attack)
RUN curl -sSL https://get.example-setup.com/install.sh | sh
RUN wget -qO- https://bootstrap.pypa.io/get-pip.py | python3

# CG_IAC_DOCKER_004 — chmod 777 (world-writable, privilege escalation)
RUN chmod 777 /app
RUN chmod -R 777 /tmp /var/log

# CG_IAC_DOCKER_005 — hardcoded secrets in ENV (visible in docker inspect / image layers)
ENV DATABASE_URL="postgres://admin:SuperSecret123@prod-db.internal:5432/myapp"
ENV AWS_ACCESS_KEY_ID="AKIAFAKEKEYIDEXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="FaKeAwSsEcReTkEyFaKeAwSsEcReT1234"
ENV OPENAI_API_KEY="sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcde"
ENV JWT_SECRET="hardcoded-jwt-secret-do-not-do-this"

# CG_IAC_DOCKER_006 — --no-check-certificate / --insecure (disables TLS verification)
RUN wget --no-check-certificate https://internal.example.com/setup.tar.gz
RUN curl --insecure https://get.example.com/agent -o agent

COPY package*.json ./
RUN npm install

COPY . .

# No HEALTHCHECK, no USER, no read-only filesystem — all bad practices
# (No USER = runs as root)

EXPOSE 3000
CMD ["node", "index.js"]
