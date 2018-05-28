FROM python:3

LABEL contributor="Shrivatsan N R <nrshrivatsan@outlook.com>"
LABEL maintainer="Dimitrios Mavrommatis <jim.mavrommatis@gmail.com>"

RUN apt-get update && \
      apt-get install -y git g++ gcc python3 python3-setuptools python3-dev traceroute python3-pip libssl-dev libffi-dev

RUN git clone https://github.com/gnomikos/traIXroute.git && \
    cd traIXroute

WORKDIR /traIXroute

RUN pip3 install -r setup/requirements.txt &&\
      python3 lib/traixroute/downloader/install_scamper.py install_scamper.py &&\
        python3 setup.py sdist bdist_wheel
WORKDIR bin/
ENTRYPOINT ["./traixroute"]
CMD ["-h"]
