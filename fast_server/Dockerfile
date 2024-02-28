FROM python:3.10-bullseye

WORKDIR /server
COPY . ./

COPY requirements.txt ./
COPY start_server.sh ./

RUN pip3 install -r requirements.txt

RUN apt install -y\
    libssl-dev \
    openssl

#RUN chmod a+x start_server.sh

RUN chmod -R 777 ./

#CMD [ "./start_server.sh" ]
CMD [ "uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"]
