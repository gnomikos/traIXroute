FROM python:3

LABEL contributor="Shrivatsan N R"
LABEL maintainer="Dimitrios Mavrommatis <jim.mavrommatis@gmail.com>"

WORKDIR /root

COPY lib/traixroute/downloader/install_scamper.py install_scamper.py

RUN pip install --no-cache-dir traixroute

RUN python install_scamper.py

RUN traixroute -u -process

ENTRYPOINT ["traixroute"]
CMD ["-h"]
