FROM debian:bookworm

RUN apt-get update && apt-get install -y libssl-dev

WORKDIR "/usr/share/auth2"
CMD ["/usr/bin/auth2"]
