#/bin/bash

source env/bin/activate && uvicorn --workers 4 --host 0.0.0.0 sign_file.app:app