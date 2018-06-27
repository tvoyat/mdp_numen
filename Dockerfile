FROM alpine:latest

MAINTAINER Thierry VOYAT <thierry.voyat@ac-amiens.fr>

# Pour lancer : 
RUN apk update \
    && apk add perl \
    && rm -rf /var/cache/apk/*


COPY verify_mdp.pl /usr/local/bin

VOLUME /outils

CMD ["/usr/local/bin/verify_mdp.pl", "--ldif", "/outils/export.ldif"]


