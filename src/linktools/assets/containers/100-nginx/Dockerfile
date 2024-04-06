FROM nginx:{{ NGINX_TAG }}

RUN apk --no-cache add openssl socat
RUN curl https://get.acme.sh | sh -s email=acme@google.com && \
    ln -s ~/.acme.sh/acme.sh /usr/bin/acme.sh && \
    acme.sh --set-default-ca --server letsencrypt

RUN echo "#!/bin/sh" > /docker-entrypoint.d/99-start-crond.sh \
    && echo "crond" >> /docker-entrypoint.d/99-start-crond.sh \
    && chmod +x /docker-entrypoint.d/99-start-crond.sh

RUN mkdir -p /etc/certs

{% for key in container.keys -%}
    {% with value = config.get(key, default=None) -%}
        {% if value %}
ENV {{ key }} {{ value }}
        {% endif %}
    {%- endwith %}
{%- endfor %}

RUN acme.sh --issue --debug --domain {{ ROOT_DOMAIN }} --domain *.{{ ROOT_DOMAIN }} --dns {{ ACME_DNS_API }}

RUN acme.sh --install-cert --domain {{ ROOT_DOMAIN }} --domain *.{{ ROOT_DOMAIN }} \
    --cert-file /etc/certs/{{ ROOT_DOMAIN }}_cert.pem \
    --key-file /etc/certs/{{ ROOT_DOMAIN }}_key.pem \
    --fullchain-file /etc/certs/{{ ROOT_DOMAIN }}_fullchain.pem \
    --reloadcmd "nginx -s reload 2>/dev/null || true"
