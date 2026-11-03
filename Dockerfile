FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir '.[ui,mcp,agent]'
EXPOSE 8501
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501"]
