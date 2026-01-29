# Use a lightweight Python image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy application files
COPY main.py .
COPY templates templates

# Install Flask
RUN pip install --no-cache-dir flask

# Expose the port Flask runs on
EXPOSE 8080

# Run the application
CMD ["python", "main.py"]
