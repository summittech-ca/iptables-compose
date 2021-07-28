FROM alpine AS base

RUN apk update && \
    apk add cargo git

COPY . iptables-compose
RUN cargo install --path iptables-compose && \
    rm -rf iptables-compose

FROM alpine
COPY --from=base /root/.cargo/bin/iptables-compose /opt/bin/iptables-compose
RUN apk --update --no-cache add libgcc iptables