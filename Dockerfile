FROM ubuntu:latest

RUN apt-get update && \
  apt-get install -y g++ lldb make cmake pkg-config libhyperscan-dev libpcre3-dev libgtest-dev

WORKDIR /usr/src/gtest
RUN cmake CMakeLists.txt && make && make install

CMD /bin/bash
