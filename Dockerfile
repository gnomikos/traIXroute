FROM python:3

LABEL contributor="Shrivatsan N R <nrshrivatsan@outlook.com>"
LABEL maintainer="Dimitrios Mavrommatis <jim.mavrommatis@gmail.com>"

RUN apt-get update && \
      apt-get install -y g++ gcc python3 python3-setuptools python3-dev traceroute python3-pip libssl-dev libffi-dev

COPY lib /traixroute/lib
COPY setup/requirements.txt /traixroute/requirements.txt
COPY README.rst /traixroute/README.rst

COPY setup.py /traixroute/setup.py
WORKDIR /traixroute
RUN ls -lrth
RUN pip3 install -r requirements.txt &&\
      python3 lib/traixroute/downloader/install_scamper.py install_scamper.py &&\
        python3 setup.py install
RUN traixroute -u -process
ENTRYPOINT ["traixroute"]
CMD ["-h"]
