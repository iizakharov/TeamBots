FROM python:3.8.10

WORKDIR /opt/sc_bot

# переменные окружения для python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# устанавливаем зависимости
RUN pip install --upgrade pip

COPY . .

#COPY requirements.txt .
RUN pip install -r requirements.txt

CMD ["python3", "main.py"]

# docker build -t scbots/sc_bot:1.0 .
# docker run -ti --name sc_bot scbots/sc_bot:1.0
