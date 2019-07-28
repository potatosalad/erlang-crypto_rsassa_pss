ARG OTP_VERSION=alpine
FROM erlang:${OTP_VERSION}-alpine

# Setup environment
ENV LANG=C.UTF-8 TERM=xterm

# Add dependencies
RUN apk upgrade --update musl && \
    apk add --no-cache bash bc curl git make openssl rsync unzip && \
    rm -rf /var/cache/apk/*

RUN mkdir /build
WORKDIR /build

# FROM ubuntu:19.04

# ARG OTP_VERSION=local
# ENV OTP_VERSION ${OTP_VERSION}

# RUN apt-get update && \
#     apt-get -y install curl gnupg2 && \
#     curl -O https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb && \
#     dpkg -i erlang-solutions_1.0_all.deb && \
#     echo "deb https://packages.erlang-solutions.com/ubuntu disco contrib" > /etc/apt/sources.list.d/erlang-solutions.list && \
#     apt-get update && \
#     echo apt-get -y install esl-erlang=1:${OTP_VERSION}\* git make clang-8 autoconf automake libtool locales openssl libssl-dev && \
#     apt-get -y install git make clang-8 autoconf automake libtool locales openssl libssl-dev && \
#     sed -i 's/^# \(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen && \
#     locale-gen

# ENV LANG en_US.UTF-8
# ENV CC clang-8
# ENV CXX clang++-8
# ENV ARCHFLAGS -Wgcc-compat
# ENV MIX_ENV test

# RUN mkdir /build
# WORKDIR /build
