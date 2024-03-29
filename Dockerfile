FROM almalinux:8

RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="powertools" --enablerepo="epel" \
        python39 python39-devel python3-virtualenv python39-setuptools pinentry gnupg2  && \
    dnf clean all


RUN groupadd -g 1000 alt && \
    useradd -ms /bin/bash -u 1000 -g 1000 alt && \
    usermod -aG wheel alt && \
    echo 'alt ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    echo 'wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers


WORKDIR /app
RUN virtualenv -p python3.9 env
COPY setup.py /app
RUN /app/env/bin/pip install -e /app/.

RUN chown -R alt:alt /app
USER alt

CMD ["/app/env/bin/python", "/app/start.py"]
