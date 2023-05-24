# Use the official Python base image
FROM python:3.11

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the project dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files to the working directory
COPY . .

# Expose the port that FastAPI uses
EXPOSE 5050

# Run the FastAPI application
CMD ["python","-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5050"]
