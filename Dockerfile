FROM almalinux/9-base:latest AS sign-file

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
  rm -rf setup.py ~/.cache/pip
EOT


FROM sign-file AS sign-file-tests

COPY requirements-tests.txt setup.py .
RUN <<EOT
  set -ex
  pip3 install -r requirements-tests.txt
  # The KMS backend is an optional extra, so its dependencies are absent from
  # the runtime image. The KMS tests drive it with a stubbed AWS client, but
  # still need boto3 and pgpy importable.
  pip3 install '.[kms]'
  rm -rf requirements-tests.txt setup.py ~/.cache/pip
EOT
