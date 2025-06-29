# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Intall build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libgmp-dev \
    libssl-dev \
    libffi-dev \
    python3-dev \
    git \
    wget \
    autoconf \
    autoconf-archive \
    flex \
    bison \
    libtool \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install PBC from source
RUN git clone https://github.com/blynn/pbc.git /pbc && \
    cd /pbc && \
    git checkout 1b5d226de4788bdcd1d47781c746c4192de5b69c && \
    mkdir m4 && \
    wget "http://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/ax_cxx_compile_stdcxx.m4" -O m4/ax_cxx_compile_stdcxx.m4 && \
    wget "https://git.savannah.gnu.org/gitweb/?p=autoconf-archive.git;a=blob_plain;f=m4/ax_cxx_compile_stdcxx_14.m4" -O m4/ax_cxx_compile_stdcxx_14.m4 && \
    export ACLOCAL_PATH=/usr/share/aclocal && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd /app

# Clone and install Charm-Crypto from source
RUN git clone https://github.com/JHUISI/charm.git /charm && \
    cd /charm && \
    git checkout bf9933fe843a0b78c07991452114fc4e4be2e71a && \
    ./configure.sh && \
    make && \
    make install && \
    pip install -e /charm && \
    cd /app

# Copy the requirements file
COPY requirements.txt /app/

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copy the rest of the application code
COPY . /app/

# Expose the port the app runs on
EXPOSE 8080
# debug port
EXPOSE 5678

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--threads", "10", "--preload" "run:app"]

# ENTRYPOINT ["python", "-m", "watchmedo", "auto-restart", "--directory=.", "--pattern=*", "--recursive", "--", "python", "-m", "debugpy", "--listen", "0.0.0.0:5679", "run.py"]

# Debugging
# CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5679", "run.py"]

# Development
# CMD ["watchmedo", "auto-restart", "--directory=.", "--pattern=*.py", "--recursive", "--", "python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "run.py"]