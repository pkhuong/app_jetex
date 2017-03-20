FROM python:3.5-alpine

RUN pip3 install dnspython

COPY reusesocketd.py /src/reusesocketd.py

VOLUME /var/shared_run

WORKDIR /var/shared_run
ENTRYPOINT ["python3", "/src/reusesocketd.py", "-e", \
	    "--drop", "nobody:nogroup", "-w", "reusesocketd.sock"]
# docker run --network=host -v /var/run:/var/shared_run reusesocketd
CMD []
