FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

ENV FLAG="CTF{f1lt3r_byp4ss_c0mm3nt_tr1ck}"

EXPOSE 5000

CMD ["python", "app.py"]
