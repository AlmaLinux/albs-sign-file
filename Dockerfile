FROM almalinux:8

RUN curl https://packages.codenotary.org/codenotary.repo -o /etc/yum.repos.d/codenotary.repo

RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="powertools" --enablerepo="epel" --enablerepo="codenotary-repo" \
        python39 python39-devel python3-virtualenv python39-setuptools pinentry gnupg2  && \
    dnf clean all

RUN useradd -ms /bin/bash alt
RUN usermod -aG wheel alt
RUN echo 'alt ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN echo 'wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers


WORKDIR /app
RUN virtualenv -p python3.9 env
COPY setup.py /app/setup.py
COPY start.py /app/start.py
COPY .env /app/
COPY db_manage.py /app
RUN /app/env/bin/pip install -e /app/.

RUN chown -R alt:alt /app
USER alt

CMD ["/app/env/bin/python", "/app/start.py"]
