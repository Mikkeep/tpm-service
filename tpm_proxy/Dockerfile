#TPM2 simulator with alpine base
FROM alpine:3.13.6

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8

# Installing needed dependecies and tools for developing

RUN apk update && \
    apk add \
    acl \
    autoconf \
    autoconf-archive \
    automake \
    libtool \
    build-base \
    pkgconf \
    doxygen \
    json-c-dev \
    openssl \
    openssl-dev \
    libssl1.1 \
    git \
    udev \
    dbus \
    curl-dev \
    linux-headers \
    glib-dev \
    libconfig-dev \
    libgcrypt-dev \
    shadow \
    wget \
    python3 \
    py3-pip

RUN mkdir tpm2
WORKDIR /tpm2
RUN mkdir ibmsim

WORKDIR /tpm2
RUN git clone --branch 3.0.x https://github.com/tpm2-software/tpm2-tss.git && \
    git clone https://github.com/tpm2-software/tpm2-abrmd.git && \
    git clone https://github.com/tpm2-software/tpm2-tools.git

WORKDIR /tpm2/tpm2-tss
RUN ./bootstrap && \
    ./configure --with-udevrulesprefix && \
    make -j4 && \
    make install

WORKDIR /tpm2/tpm2-abrmd
RUN ./bootstrap && \
    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d && \
    make -j4 && \
    make install

WORKDIR /tpm2/tpm2-tools
RUN ./bootstrap && \
    ./configure && \
    make -j4 && \
    make install


WORKDIR /tpm2/ibmsim
RUN wget --quiet --show-progress --progress=dot:giga --no-check-certificate "https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1661.tar.gz"
RUN tar -xf ibmtpm1661.tar.gz
WORKDIR /tpm2/ibmsim/src
RUN make -j4
RUN cp tpm_server /bin/


RUN pip install --upgrade pip

COPY requirements.txt /tpm2/

RUN pip3 install -r /tpm2/requirements.txt

WORKDIR /

COPY tpmStartup.sh /bin/

RUN chmod a+x /bin/tpmStartup.sh

CMD ["/bin/tpmStartup.sh"]

#The Clear BSD License

#Copyright (c) 2020 Nokia
#All rights reserved.

#Redistribution and use in source and binary forms, with or without
#modification, are permitted (subject to the limitations in the disclaimer
#below) provided that the following conditions are met:

#     * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.

#     * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.

#     * Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from this
#     software without specific prior written permission.

#NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
#THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
#CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
#IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#POSSIBILITY OF SUCH DAMAGE.
