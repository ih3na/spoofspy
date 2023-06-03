from fastapi import FastAPI, Request
import sniff as snf

app = FastAPI()

capture = snf.captured_data

@app.get("/")
async def root():
    return {"message": "hello from root"}

@app.get("/stats")
async def index():
    data = []
    while not (capture.empty()):
        await data.append(capture.get())
    return {"data": data}

@app.post("/")
async def update_interface(request: Request):
    form = await request.form()
    global expected_interface
    expected_interface = form["interface"]
    return {"message": "Interface updated successfully"}

