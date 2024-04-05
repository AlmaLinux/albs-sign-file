FROM almalinux:9 as sign-file

RUN <<EOT
  set -ex
  dnf upgrade -y
  dnf install -y pinentry
  dnf clean all
EOT

WORKDIR /app
COPY setup.py .
RUN <<EOT
  set -ex
  python3 -m ensurepip
  pip3 install .
  rm setup.py
EOT


FROM sign-file as sign-file-tests

COPY requirements-tests.txt .
RUN <<EOT
  set -ex
  pip3 install -r requirements-tests.txt
  rm requirements-tests.txt
EOT