FROM python:3.12-alpine AS poc-base

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 22

############################################################
## Sequence Number Manipulations (Section 4.1)            ##
############################################################
FROM poc-base AS sqn-rcv-decrease
ENTRYPOINT [ "python", "sqn-manipulations/rcv_decrease.py" ]

FROM poc-base AS sqn-rcv-increase
ENTRYPOINT [ "python", "sqn-manipulations/rcv_increase.py" ]

FROM poc-base AS sqn-snd-decrease
ENTRYPOINT [ "python", "sqn-manipulations/snd_decrease.py" ]

FROM poc-base AS sqn-snd-increase
ENTRYPOINT [ "python", "sqn-manipulations/snd_increase.py" ]

############################################################
## Extension Downgrade (Section 5.2 / Figure 5)           ##
############################################################
FROM poc-base AS ext-downgrade-chacha20-poly1305
ENTRYPOINT ["python", "ext-downgrade/ext_downgrade_chacha20_poly1305.py" ]

FROM poc-base AS ext-downgrade-cbc-unknown
ENTRYPOINT [ "python", "ext-downgrade/ext_downgrade_cbc_unknown.py" ]

FROM poc-base AS ext-downgrade-cbc-ping
ENTRYPOINT [ "python", "ext-downgrade/ext_downgrade_cbc_ping.py" ]

############################################################
## Attacks on AsyncSSH (Section 6.1-6.2 / Figure 6-7)     ##
############################################################
FROM poc-base AS asyncssh-rogue-extension-negotiation
ENTRYPOINT ["python", "asyncssh/rogue_extension_negotiation.py"]

FROM poc-base AS asyncssh-rogue-session-attack
ENTRYPOINT ["python", "asyncssh/rogue_session_attack.py"]
